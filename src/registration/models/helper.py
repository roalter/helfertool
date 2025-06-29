from django.conf import settings
from django.core.mail import EmailMessage
from django.urls import reverse
from django.db import models
from django.db.models.signals import m2m_changed, post_save
from django.dispatch import receiver
from django.template.loader import get_template
from django.utils import translation
from django.utils.translation import gettext_lazy as _

from badges.models import Badge
from gifts.models import HelpersGifts
from mail.tracking import new_tracking_registration
from prerequisites.models import Prerequisite

from .event import Event
from .helpershift import HelperShift
from .job import Job

from smtplib import SMTPException

import uuid

import logging

logger = logging.getLogger("helfertool.registration")


class EmailMessageNG(EmailMessage):
    def __init__(self, subject="", body="", from_email=None, to=None, bcc=None, connection=None, attachments=None,
                 headers=None, cc=None, reply_to=None, sender=None):

        super().__init__(subject, body, from_email, to, bcc, connection, attachments, headers, cc, reply_to)
        self.sender = sender

    def message(self):
        result = super().message()
        if self.sender is not None and self.sender != self.from_email:
            result["Sender"] = self.sender
        return result


class Helper(models.Model):
    """Helper in one or more shifts.

    Columns:
        :shifts: all shifts of this person
        :firstname: the firstname
        :surname: the surname
        :email: the e-mail address
        :phone: phone number
        :comment: optional comment
        :internal_comment: optional internal comment
        :shirt: t-shirt size (possible sizes are defined here)
        :nutrition: is the helper vegetarian/vegan/...?
        :infection_instruction: status of the instruction for food handling
        :timestamp: time of registration
        :validated: the validation link was clicked (if validation is enabled)
        :timestamp_validated: time when validation link was clicked (if validation is enabled)
        :validation_id: Additional UUID for mail validation link, so that we prevent guessing of the URL
        :mail_failed: a "undelivered" report returned for the registration mail
        :privacy_statement: the privacy statement was accepted
    """

    class Meta:
        ordering = ["event", "surname", "firstname"]

    # choices for food handling inctruction (short texts used internalls, normal ones in registration form)
    INSTRUCTION_NO = "No"
    INSTRUCTION_YES = "Yes"
    INSTRUCTION_REFRESH = "Refresh"

    INSTRUCTION_CHOICES = (
        (INSTRUCTION_NO, _("I never got an instruction")),
        (INSTRUCTION_YES, _("I have a valid instruction")),
        (INSTRUCTION_REFRESH, _("I got a instruction by a doctor, it must be refreshed")),
    )

    INSTRUCTION_CHOICES_SHORT = (
        (INSTRUCTION_NO, _("No")),
        (INSTRUCTION_YES, _("Valid")),
        (INSTRUCTION_REFRESH, _("Refreshment")),
    )

    # choices for nutrition (short texts used internalls, normal ones in registration form)
    NUTRITION_NO_PREFERENCE = "NO_PREFERENCE"
    NUTRITION_VEGETARIAN = "VEGETARIAN"
    NUTRITION_VEGAN = "VEGAN"
    NUTRITION_OTHER = "OTHER"

    NUTRITION_CHOICES = (
        (NUTRITION_NO_PREFERENCE, _("No preference")),
        # Translators: adjective
        (NUTRITION_VEGETARIAN, _("Vegetarian")),
        (NUTRITION_VEGAN, _("Vegan")),
        (NUTRITION_OTHER, _("Other (please specify in comment)")),
    )

    NUTRITION_CHOICES_SHORT = (
        (NUTRITION_NO_PREFERENCE, _("No preference")),
        # Translators: adjective
        (NUTRITION_VEGETARIAN, _("Vegetarian")),
        (NUTRITION_VEGAN, _("Vegan")),
        (NUTRITION_OTHER, _("Other")),
    )

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )

    shifts = models.ManyToManyField(
        "Shift",
        through=HelperShift,
    )

    event = models.ForeignKey(
        Event,
        on_delete=models.CASCADE,
    )

    firstname = models.CharField(
        max_length=200,
        verbose_name=_("First name"),
    )

    surname = models.CharField(
        max_length=200,
        verbose_name=_("Surname"),
    )

    email = models.EmailField(
        verbose_name=_("E-Mail"),
    )

    phone = models.CharField(
        max_length=200,
        verbose_name=_("Mobile phone"),
    )

    grade = models.CharField(
        max_length=20,
        blank=True,
        verbose_name=_("Grade or Department"),
    )

    comment = models.CharField(
        max_length=200,
        blank=True,
        verbose_name=_("Comment"),
    )

    internal_comment = models.TextField(
        blank=True,
        verbose_name=_("Internal comment"),
    )

    shirt = models.CharField(
        max_length=20,
        choices=Event.SHIRT_CHOICES,
        default=Event.SHIRT_UNKNOWN,
        verbose_name=_("T-shirt"),
    )

    nutrition = models.CharField(
        max_length=20,
        choices=NUTRITION_CHOICES,
        default=NUTRITION_NO_PREFERENCE,
        verbose_name=_("Nutrition"),
        help_text=_("This helps us estimating the food for our helpers."),
    )

    infection_instruction = models.CharField(
        max_length=20,
        choices=INSTRUCTION_CHOICES,
        blank=True,
        verbose_name=_("Instruction for the handling of food"),
    )

    timestamp = models.DateTimeField(auto_now_add=True, verbose_name=_("Registration time for the helper"))

    validated = models.BooleanField(
        default=False,
        verbose_name=_("E-Mail address was confirmed"),
    )

    timestamp_validated = models.DateTimeField(
        blank=True,
        null=True,
    )

    validation_id = models.UUIDField(
        default=uuid.uuid4,
        editable=False,
    )

    mail_failed = models.CharField(
        blank=True,
        null=True,
        default=None,
        max_length=512,
    )

    privacy_statement = models.BooleanField(
        default=False,
        verbose_name=_("I agree with the data privacy statement."),
    )

    prerequisites = models.ManyToManyField(
        Prerequisite,
        through="prerequisites.FulfilledPrerequisite",
        blank=True,
    )

    def __str__(self):
        return "%s %s" % (self.firstname, self.surname)

    def get_infection_instruction_short(self):
        """Returns the short description for the infection_instruction field."""
        for item in Helper.INSTRUCTION_CHOICES_SHORT:
            if item[0] == self.infection_instruction:
                return item[1]
        return ""

    def get_nutrition_short(self):
        """Returns the short description for the nutrition field."""
        for item in Helper.NUTRITION_CHOICES_SHORT:
            if item[0] == self.nutrition:
                return item[1]
        return ""

    @property
    def needs_infection_instruction(self):
        # check shifts
        for shift in self.shifts.all():
            if shift.job.infection_instruction:
                return True

        # check coordinated jobs
        for job in self.coordinated_jobs:
            if job.infection_instruction:
                return True

        return False

    def send_mail(self, request, internal, language=None):
        """Send a confirmation e-mail to the registered helper.

        This e-mail contains a list of the shifts, the helper registered for.
        """
        # safety check ;)
        if self.shifts.count() == 0 and not self.is_coordinator:
            return

        # generate URLs
        event = self.event
        validate_url = request.build_absolute_uri(
            reverse("validate", args=[event.url_name, self.id, self.validation_id])
        )
        registered_url = request.build_absolute_uri(reverse("registered", args=[event.url_name, self.id]))

        # generate subject and text from templates
        if language:
            prev_language = translation.get_language()
            translation.activate(language)

        subject_template = get_template("registration/mail/subject.txt")
        subject = subject_template.render({"event": event}).rstrip()

        if self.is_coordinator:
            text_template = get_template("registration/mail/coordinator.txt")
        elif internal:
            text_template = get_template("registration/mail/internal.txt")
        else:
            text_template = get_template("registration/mail/public.txt")
        text = text_template.render(
            {
                "user": self,
                "event": event,
                "validate_url": validate_url,
                "registered_url": registered_url,
                #"contact_mail": settings.CONTACT_MAIL,
                "contact_mail": event.email,
            }
        )

        if language:
            translation.activate(prev_language)

        # header for mail tracking
        tracking_header = new_tracking_registration(self)

        sender = settings.EMAIL_SENDER_ADDRESS
        if settings.EMAIL_SENDER_NAME != sender:
            sender = f"{settings.EMAIL_SENDER_NAME} <{sender}>"

        # sent it and handle errors
        mail = EmailMessageNG(
            subject,
            text,
            sender,
            [
                self.email,
            ],  # to
            reply_to=[
                event.email,
            ],
            sender=event.email,
            headers=tracking_header,
        )

        try:
            mail.send(fail_silently=False)
            return True
        except (SMTPException, ConnectionError) as e:
            self.mail_failed = "Local server error"
            self.save()

            logger.error(
                "helper mailerror",
                extra={
                    "event": event,
                    "helper": self,
                    "error": str(e),
                },
            )

            return False

    def check_delete(self):
        if self.shifts.count() == 0 and not self.is_coordinator:
            self.delete()

    def has_missed_shift(self, shift=None):
        if not self.event.gifts:
            return False

        if shift is None:
            return self.helpershift_set.filter(present=False, manual_presence=True).exists()
        else:
            return self.helpershift_set.filter(present=False, manual_presence=True, shift=shift).exists()

    @property
    def full_name(self):
        """Returns full name of helper"""
        return "%s %s" % (self.firstname, self.surname)

    @property
    def has_to_validate(self):
        return not self.validated

    @property
    def coordinated_jobs(self):
        if hasattr(self, "job_set"):
            return getattr(self, "job_set").all()
        return []

    @property
    def is_coordinator(self):
        if not hasattr(self, "job_set"):
            return False
        return getattr(self, "job_set").count() > 0

    @property
    def first_shift(self):
        shifts = self.shifts.order_by("begin")
        if len(shifts) > 0:
            return shifts[0]
        return None

    @property
    def all_jobs(self):
        """Returns all jobs, which are done by the helper (as coordinator or helper)"""
        jobs = set(self.coordinated_jobs)

        for shift in self.shifts.prefetch_related("job"):
            jobs.add(shift.job)

        return jobs


@receiver(post_save, sender=Helper, dispatch_uid="helper_saved")
def helper_saved(sender, instance, using, **kwargs):
    """Add badge and gifts to helper if necessary.

    This is a signal handler, that is called, when a helper is saved. It
    adds the badge if badge creation is enabled and it is not there already.
    """
    if instance.event:
        if instance.event.badges and not hasattr(instance, "badge"):
            badge = Badge()
            badge.event = instance.event
            badge.helper = instance
            badge.save()

        if instance.event.gifts and not hasattr(instance, "gifts"):
            gifts = HelpersGifts()
            gifts.helper = instance
            gifts.save()


def helper_deleted(sender, **kwargs):
    action = kwargs.pop("action")

    if action == "post_remove":
        helper = kwargs.pop("instance")
        helper.check_delete()


def coordinator_deleted(sender, **kwargs):
    action = kwargs.pop("action")

    if action == "post_remove":
        pk_set = kwargs.pop("pk_set")
        model = kwargs.pop("model")  # this is Helper

        # iterate over all deleted helpers, this should be only one helper
        for helper_pk in pk_set:
            helper = model.objects.get(pk=helper_pk)
            helper.check_delete()


m2m_changed.connect(helper_deleted, sender=Helper.shifts.through)
m2m_changed.connect(coordinator_deleted, sender=Job.coordinators.through)
