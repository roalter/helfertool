from django.urls import path
from django.views.generic import TemplateView

from . import views

app_name = "help"
urlpatterns = [
    path("help/", views.create_issue, name="create_issue"),
    path("help/imprint/", TemplateView.as_view(template_name="help/imprint.html"), name="show_imprint"),
    path("help/privacy/", TemplateView.as_view(template_name="help/privacy.html"), name="show_privacy"),
]
