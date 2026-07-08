from django.contrib import admin
from django.conf import settings
from django.conf.urls.static import static
from django.urls import path, include
from risks import views  # <--- IF THIS IS MISSING, IT WILL FAIL

urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/', include('django.contrib.auth.urls')),
    
    # --- THIS IS THE LINE YOUR COMPUTER IS MISSING ---
    path('official-report/', views.official_report, name='official_report'),
    # -------------------------------------------------

    path('', include('risks.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
