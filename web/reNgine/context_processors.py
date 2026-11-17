from dashboard.models import *
from django.conf import settings


def projects(request):
    projects = Project.objects.all()
    slug = None
    if getattr(request, 'resolver_match', None):
        slug = request.resolver_match.kwargs.get('slug')
    project = Project.objects.filter(slug=slug).first() if slug else None
    if project is None:
        # Pages without a project in the URL (e.g. 404) still render the
        # navigation, which needs a project slug.
        project = projects.order_by('id').first()
    return {
        'projects': projects,
        'current_project': project
    }

def version_context(request):
    return {
        'RENGINE_CURRENT_VERSION': settings.RENGINE_CURRENT_VERSION
    }

def user_preferences(request):
    if hasattr(request, 'user_preferences'):
        return {'user_preferences': request.user_preferences}
    return {}