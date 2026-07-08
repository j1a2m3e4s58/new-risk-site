from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('risk-ai/', views.compliance_assistant, name='compliance-assistant'),
    path('risks/add/', views.risk_create, name='risk-create'),
    path('risks/<int:risk_id>/', views.risk_detail, name='risk-detail'),
    path('risks/<int:risk_id>/edit/', views.risk_update, name='risk-edit'),
    path('risks/<int:risk_id>/action/', views.risk_action_update, name='risk-action-update'),
    path('risks/<int:risk_id>/incident/', views.incident_create, name='risk-incident-create'),
    path('risks/<int:risk_id>/delete/', views.risk_delete, name='risk-delete'),
    path('customer-profiles/', views.customer_profile_list, name='customer-profile-list'),
    path('customer-profiles/<int:profile_id>/', views.customer_profile_detail, name='customer-profile-detail'),
    path('departments/<path:area_name>/', views.department_detail, name='department-detail'),
    path('calendar/', views.risk_calendar, name='risk-calendar'),
    path('incidents/add/', views.incident_create, name='incident-create'),
    path('audit-log/', views.audit_log, name='audit-log'),
    path('notifications/', views.notifications_panel, name='notifications'),
    path('backup/', views.backup_tools, name='backup-tools'),
    path('backup/download/', views.backup_database, name='backup-database'),
    path('backup/restore/', views.restore_database, name='restore-database'),
    path('backup/system-package/', views.export_system_package, name='export-system-package'),
    path('export-csv/', views.export_risks_csv, name='export-csv'),
    path('executive-dashboard/', views.executive_dashboard, name='executive-dashboard'),

    path('export-csv-clear/', views.export_risks_csv_and_clear, name='export-csv-clear'),
    path('clear-risks/', views.clear_all_risks, name='clear-risks'),

    path('ai-extract/', views.ai_extract_risks, name='ai-extract'),
    path('ai-extract/save/', views.ai_extract_save_drafts, name='ai-extract-save'),
    path('ai-extract/save-approve/', views.ai_extract_save_and_approve, name='ai-extract-save-approve'),

    path('draft/<int:risk_id>/edit/', views.edit_draft_risk, name='edit-draft-risk'),
    path('drafts/approve-all/', views.bulk_approve_drafts, name='bulk-approve-drafts'),

    path('board-explanation/', views.board_explanation, name='board-explanation'),
]
