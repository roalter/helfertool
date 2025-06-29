from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.validators import MinValueValidator, RegexValidator
from django.db import models
from django.db.models.signals import pre_save, post_save, post_delete
from django.dispatch import receiver
from django.utils.translation import gettext_lazy as _
from django_bleach.models import BleachField
from multiselectfield import MultiSelectField

from badges.models import BadgeSettings, BadgeDefaults, Badge
from corona.models import CoronaSettings
from gifts.models import HelpersGifts
from gifts.models.giftsettings import GiftSettings
from helfertool.forms import RestrictedImageField
from inventory.models import InventorySettings

import datetime
import os
import posixpath
import shutil
import uuid


def _default_mail():
    return settings.EMAIL_SENDER_ADDRESS


def _logo_upload_path(instance, filename):
    event = str(instance.pk)
    new_filename = "{}{}".format(uuid.uuid4(), os.path.splitext(filename)[1])

    return posixpath.join("public", event, "logos", new_filename)


def _validate_url_blocklist(value):
    """Validator for `url_name` parameter that blocks values that are part of other URLs like "subscribe"."""
    blocked = ["manage", "i18n", "select2", "login", "logout", "oidc", "help", "subscribe", "unsubscribe"]

    if value.lower() in blocked:
        raise ValidationError(_("%(value)s cannot be used here"), params={"value": value})


class Event(models.Model):
    class Meta:
        ordering = ["name", "url_name"]

    """ Event for registration.

    Columns:
        :url_name: the ID of the event used in URLs
        :name: the name of the event
        :text: text at begin of registration
        :imprint: text at the bottom if the registration page
        :registered: text after the successful registration
        :email: e-mail address used as sender of automatic e-mails
        :active: is the registration opened?
        :admins: list of admins of this event, they can see and edit everything
        :ask_shirt: ask for the t-shirt size during registration
        :ask_phone: ask for the mobile phone number during registration
        :ask_nutrition: ask, if the helper is vegetarian/vegan/...
        :show_public_numbers: show the number of current and maximal helpers on
                             the registration page
        :badge: use the badge creation system
    """

    SHIRT_UNKNOWN = "UNKNOWN"
    SHIRT_NO = "NO"
    SHIRT_XXS = "XXS"
    SHIRT_XS = "XS"
    SHIRT_S = "S"
    SHIRT_M = "M"
    SHIRT_L = "L"
    SHIRT_XL = "XL"
    SHIRT_XXL = "XXL"
    SHIRT_3XL = "3XL"
    SHIRT_4XL = "4XL"
    SHIRT_XXS_GIRLY = "XXS_GIRLY"
    SHIRT_XS_GIRLY = "XS_GIRLY"
    SHIRT_S_GIRLY = "S_GIRLY"
    SHIRT_M_GIRLY = "M_GIRLY"
    SHIRT_L_GIRLY = "L_GIRLY"
    SHIRT_XL_GIRLY = "XL_GIRLY"
    SHIRT_XXL_GIRLY = "XXL_GIRLY"
    SHIRT_3XL_GIRLY = "3XL_GIRLY"
    SHIRT_4XL_GIRLY = "4XL_GIRLY"

    SHIRT_CHOICES = (
        (SHIRT_UNKNOWN, _("Unknown")),
        (SHIRT_NO, _("I do not want a T-Shirt")),
        (SHIRT_XXS, _("XXS")),
        (SHIRT_XS, _("XS")),
        (SHIRT_S, _("S")),
        (SHIRT_M, _("M")),
        (SHIRT_L, _("L")),
        (SHIRT_XL, _("XL")),
        (SHIRT_XXL, _("XXL")),
        (SHIRT_3XL, _("3XL")),
        (SHIRT_4XL, _("4XL")),
        (SHIRT_XXS_GIRLY, _("XXS (girly)")),
        (SHIRT_XS_GIRLY, _("XS (girly)")),
        (SHIRT_S_GIRLY, _("S (girly)")),
        (SHIRT_M_GIRLY, _("M (girly)")),
        (SHIRT_L_GIRLY, _("L (girly)")),
        (SHIRT_XL_GIRLY, _("XL (girly)")),
        (SHIRT_XXL_GIRLY, _("XXL (girly)")),
        (SHIRT_3XL_GIRLY, _("3XL (girly)")),
        (SHIRT_4XL_GIRLY, _("4XL (girly)")),
    )

    SHIRT_CHOICES_DEFAULTS = (
        SHIRT_S,
        SHIRT_M,
        SHIRT_L,
        SHIRT_XL,
        SHIRT_XXL,
        SHIRT_S_GIRLY,
        SHIRT_M_GIRLY,
        SHIRT_L_GIRLY,
        SHIRT_XL_GIRLY,
    )

    name = models.CharField(
        max_length=200,
        verbose_name=_("Event name"),
    )

    url_name = models.SlugField(
        max_length=200,
        unique=True,
        validators=[_validate_url_blocklist],
        verbose_name=_("Name for URL"),
        help_text=_("May contain letters, numbers, underscores or hyphens."),
    )

    date = models.DateField(
        verbose_name=_("Date"),
        help_text=_("First day of event"),
    )

    days = models.IntegerField(
        default=1,
        verbose_name=_("Number of days"),
        help_text=_("Displayed on the main page"),
        validators=[MinValueValidator(0)],
    )

    text = BleachField(
        blank=True,
        verbose_name=_("Text before registration"),
        help_text=_("Displayed as first text of the registration form."),
    )

    imprint = BleachField(
        blank=True,
        verbose_name=_("Contact"),
        help_text=_("Displayed at the bottom of all pages for the event."),
    )

    registered = BleachField(
        blank=True,
        verbose_name=_("Text after registration"),
        help_text=_("Displayed after registration."),
    )

    email = models.EmailField(
        default=_default_mail,
        verbose_name=_("E-Mail"),
        help_text=_("Used as Reply-to address for mails sent to helpers"),
    )

    # note: there is code to duplicate the file in forms/event.py
    logo = RestrictedImageField(
        upload_to=_logo_upload_path,
        blank=True,
        null=True,
        verbose_name=_("Logo"),
    )

    # note: there is code to duplicate the file in forms/event.py
    logo_social = RestrictedImageField(
        upload_to=_logo_upload_path,
        blank=True,
        null=True,
        verbose_name=_("Logo for Facebook"),
        help_text=_("Best results with 1052 x 548 px."),
    )

    max_overlapping = models.IntegerField(
        null=True,
        blank=True,
        verbose_name=_("Maximal overlapping of shifts"),
        help_text=_(
            "If two shifts overlap more than this value in minutes "
            "it is not possible to register for both shifts. Leave "
            "empty to disable this check."
        ),
    )

    admins = models.ManyToManyField(get_user_model(), blank=True, through="registration.EventAdminRoles")

    active = models.BooleanField(
        default=False,
        verbose_name=_("Registration publicly visible"),
    )

    changes_until = models.DateField(
        verbose_name=_("Deregistration and changes possible until"),
        help_text=_(
            "Helpers can change their personal data and shifts until "
            "this date themselves. Leave emtpy to disable this."
        ),
        null=True,
        blank=True,
    )

    ask_phone = models.BooleanField(
        default=True,
        verbose_name=_("Ask for phone number"),
    )

    ask_shirt = models.BooleanField(
        default=True,
        verbose_name=_("Ask for T-shirt size"),
    )

    ask_grade = models.BooleanField(
        default=True,
        verbose_name=_("Ask for grade"),
    )

    ask_nutrition = models.BooleanField(
        default=True,
        verbose_name=_("Ask for preferred nutrition"),
    )

    ask_full_age = models.BooleanField(default=True, verbose_name=_("Helpers have to confirm to be full age"))

    ask_news = models.BooleanField(
        default=True,
        verbose_name=_("Ask if helper wants to be notified about new events"),
    )

    show_public_numbers = models.BooleanField(
        default=True,
        verbose_name=_("Show number of helpers on registration page"),
    )

    badges = models.BooleanField(
        default=False,
        verbose_name=_("Use badge creation"),
    )

    gifts = models.BooleanField(
        default=False,
        verbose_name=_("Manage gifts and presence for helpers"),
    )

    inventory = models.BooleanField(
        default=False,
        verbose_name=_("Use the inventory functionality"),
    )

    prerequisites = models.BooleanField(
        default=False,
        verbose_name=_("Manage prerequisites for helpers"),
    )

    corona = models.BooleanField(
        default=False,
        verbose_name=_("Collect additional data for COVID-19 contact tracing"),
    )

    archived = models.BooleanField(
        default=False,
        verbose_name=_("Event is archived"),
    )

    shirt_sizes = MultiSelectField(
        choices=filter(lambda e: e[0] != "UNKNOWN", SHIRT_CHOICES),
        default=SHIRT_CHOICES_DEFAULTS,
        max_length=250,
        verbose_name=_("Available T-shirt sizes"),
    )

    def __str__(self):
        return self.name

    def clean(self):
        # the shirt sizes of the helpers must be selected in shirt_sizes
        # this means that it is not possible to disable a size as long one
        # helper has selected this size

        # if PK is not set (=new event), the helper_set query fails
        if self.ask_shirt and self.pk:
            not_removable = []

            new_choices = self.get_shirt_choices()
            for choice in Event.SHIRT_CHOICES:
                if choice not in new_choices and self.helper_set.filter(shirt=choice[0]).exists():
                    not_removable.append(choice[1])

            if not_removable:
                sizes = ", ".join(map(str, not_removable))
                raise ValidationError(
                    {
                        "shirt_sizes": _(
                            "The following sizes are used and " "therefore cannot be removed: {}".format(sizes)
                        )
                    }
                )

    def save(self, *args, **kwargs):
        # if we do the initial save, we do not have a PK yet, but we need the PK for the path of uploaded images
        # we therefore remove the logos temporarily, save the model, add them again and save again
        initial_save = False
        logo_original = self.logo
        logo_social_original = self.logo_social
        if not self.pk:
            initial_save = True

            self.logo = None
            self.logo_social = None

        # save
        super(Event, self).save(*args, **kwargs)

        # if it was the initial save, add logos and save again
        if initial_save:
            self.logo = logo_original
            self.logo_social = logo_social_original
            self.save(update_fields=["logo", "logo_social"])

    def get_shirt_choices(self, internal=True):
        """
        Return the valid shirt sizes in the correct format for a field's choices parameter.

        If internal is False, "Unknown" is not added.
        """
        choices = []

        for shirt in Event.SHIRT_CHOICES:
            if (shirt[0] == Event.SHIRT_UNKNOWN and internal) or shirt[0] in self.shirt_sizes:
                choices.append(shirt)

        return choices

    @property
    def badge_settings(self):
        try:
            return self.badgesettings
        except AttributeError:
            return None

    @property
    def inventory_settings(self):
        try:
            return self.inventorysettings
        except AttributeError:
            return None

    @property
    def gift_settings(self):
        try:
            return self.giftsettings
        except AttributeError:
            return None

    @property
    def corona_settings(self):
        try:
            return self.coronasettings
        except AttributeError:
            return None

    @property
    def all_coordinators(self):
        return self.helper_set.filter(job__isnull=False).distinct()

    @property
    def changes_possible(self):
        return self.changes_until is not None and datetime.date.today() <= self.changes_until

    def _setup_flags(self):
        """
        Set flags like `ask_news` depending on global settings. If a feature is disabled globally,
        this methods takes care that it is disabled for the event.

        Returns True if a value changed, otherwise False.

        Background info:
        This method is called from the pre_save handler and on startup in a Celery task.

        We want to prevent duplicated checks like "is the feature enabled for the event
        and also enabled globally?" all the time. So the event flags are used and set to `False` is a
        feature is disabled globally.
        """
        changed = False

        flags = [
            ["FEATURES_NEWSLETTER", "ask_news"],
            ["FEATURES_BADGES", "badges"],
            ["FEATURES_GIFTS", "gifts"],
            ["FEATURES_PREREQUISITES", "prerequisites"],
            ["FEATURES_INVENTORY", "inventory"],
            ["FEATURES_CORONA", "corona"],
        ]

        for flag in flags:
            # settings.FEATURE_... is False and self.... is True -> change
            if not getattr(settings, flag[0]) and getattr(self, flag[1]):
                setattr(self, flag[1], False)
                changed = True

        return changed

    def _setup_badge_settings(self):
        """
        Set up badges for all jobs and helpers (called from post_save handler).

        It adds the badge settings if badge creation is enabled and it is not there already.
        It also adds badge defaults to all jobs and badges to all helpers and coordinators if necessary.
        """
        # badge settings for event
        if not self.badge_settings:
            settings = BadgeSettings()
            settings.event = self
            settings.save()

        # badge defaults for jobs
        for job in self.job_set.all():
            if not job.badge_defaults:
                defaults = BadgeDefaults()
                defaults.save()

                job.badge_defaults = defaults
                job.save()

        # badge for helpers
        for helper in self.helper_set.all():
            if not hasattr(helper, "badge"):
                badge = Badge()
                badge.event = self
                badge.helper = helper
                badge.save()

    def _setup_gift_settings(self):
        """
        Setup gift relations for all helpers (called from post_save handler).
        """
        if not self.gift_settings:
            GiftSettings.objects.create(event=self)

        for helper in self.helper_set.all():
            if not hasattr(helper, "gifts"):
                gifts = HelpersGifts()
                gifts.helper = helper
                gifts.save()

    def _setup_inventory_settings(self):
        """
        Setup inventory settings for the event (called from post_save handler).
        """
        if not self.inventory_settings:
            InventorySettings.objects.create(event=self)

    def _setup_corona_settings(self):
        """
        Setup corona settings for the event (called from post_save handler).
        """
        if not self.corona_settings:
            CoronaSettings.objects.create(event=self)


@receiver(pre_save, sender=Event, dispatch_uid="pre_event_saved")
def pre_event_saved(sender, instance, using, **kwargs):
    """Set flags like `ask_news` depending on global settings BEFORE event is saved."""
    instance._setup_flags()


@receiver(post_save, sender=Event, dispatch_uid="post_event_saved")
def post_event_saved(sender, instance, using, **kwargs):
    """Add badge settings, badges and gifts if necessary AFTER event is saved."""
    if instance.badges:
        instance._setup_badge_settings()

    if instance.gifts:
        instance._setup_gift_settings()

    if instance.inventory:
        instance._setup_inventory_settings()

    if instance.corona:
        instance._setup_corona_settings()


@receiver(post_delete, sender=Event, dispatch_uid="event_deleted")
def event_deleted(sender, instance, using, **kwargs):
    """Delete files which were uploaded for this event."""
    event = str(instance.pk)
    for d in ["public", "private"]:
        shutil.rmtree(settings.MEDIA_ROOT / d / event, ignore_errors=True)
