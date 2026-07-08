from django.contrib import admin
from django.utils import timezone
from django.utils.html import format_html
from .models import AIAssistantAuditLog, AISettings, CustomerRiskProfile, RiskAssessment, RiskIncident, RiskTrendSnapshot, SystemAuditLog


# ========= AI SETTINGS ADMIN =========
@admin.register(AISettings)
class AISettingsAdmin(admin.ModelAdmin):
    list_display = ("enable_ai", "updated_at")


# ========= RISK ASSESSMENT ADMIN =========
class RiskTrendSnapshotInline(admin.TabularInline):
    model = RiskTrendSnapshot
    extra = 0
    can_delete = False
    readonly_fields = (
        'snapshot_date',
        'inherent_rating',
        'residual_rating',
        'action_status',
        'action_progress',
        'created_at',
    )
    fields = (
        'snapshot_date',
        'inherent_rating',
        'residual_rating',
        'action_status',
        'action_progress',
        'created_at',
    )
    ordering = ('-snapshot_date',)

    def has_add_permission(self, request, obj=None):
        return False


class RiskIncidentInline(admin.TabularInline):
    model = RiskIncident
    extra = 0
    fields = ('incident_date', 'title', 'loss_amount', 'status', 'reported_by')
    readonly_fields = ()


class CustomerRiskProfileInline(admin.TabularInline):
    model = CustomerRiskProfile
    extra = 0
    fields = ('account_no', 'account_name', 'profile_rating', 'average_score', 'total_score', 'created_at')
    readonly_fields = fields
    can_delete = False

    def has_add_permission(self, request, obj=None):
        return False


class OverdueActionFilter(admin.SimpleListFilter):
    title = "overdue action"
    parameter_name = "overdue_action"

    def lookups(self, request, model_admin):
        return (
            ("yes", "Overdue"),
            ("no", "Not overdue"),
        )

    def queryset(self, request, queryset):
        today = timezone.localdate()
        if self.value() == "yes":
            return queryset.filter(action_due_date__lt=today).exclude(action_status='Completed')
        if self.value() == "no":
            return queryset.exclude(action_due_date__lt=today).exclude(action_status='Completed') | queryset.filter(action_status='Completed')
        return queryset


@admin.register(RiskAssessment)
class RiskAssessmentAdmin(admin.ModelAdmin):
    inlines = [RiskIncidentInline, CustomerRiskProfileInline, RiskTrendSnapshotInline]
    list_display = (
        'reference_id',
        'area_name',
        'short_description',
        'workflow_status',
        'risk_owner',
        'inherent_rating_colored',
        'residual_rating_colored',
        'control_effectiveness',
        'escalation_status',
        'action_status',
        'action_progress',
        'action_due_date',
        'overdue_action_colored',
        'residual_trend_label',
        'updated_at',
        'updated_by',
        'risk_coordinator_name',

    )

    list_filter = (
        'area_name',
        'workflow_status',
        'inherent_rating',
        'residual_rating',
        'control_effectiveness',
        'escalation_status',
        'risk_owner',
        'action_status',
        OverdueActionFilter,
        'action_due_date',
    )
    search_fields = (
        'reference_id',
        'description',
        'area_name',
        'risk_owner',
        'mitigation_action',
        'action_responsible_officer',
    )
    readonly_fields = ('inherent_rating', 'residual_rating', 'escalated_at', 'created_at', 'updated_at', 'updated_by')

    fieldsets = (
        ('Risk Identification', {
    'fields': (
        ('reference_id', 'area_name'),
        'risk_owner',
        'workflow_status',
        'risk_coordinator_name',
    ),

            'description': "Basic identification details.",
        }),
        ('Risk Details', {
            'fields': ('description', 'caused_by', 'consequences'),
        }),
        ('Inherent Risk (Before Controls)', {
            'fields': (('inherent_probability', 'inherent_impact', 'inherent_rating'),),
            'description': "Select Probability and Impact.",
        }),
        ('Risk Mitigation', {
            'fields': (
                'controls',
                'control_owner',
                'control_effectiveness',
                'control_effectiveness_rationale',
            ),
        }),
        ('Action Plan', {
            'fields': (
                'mitigation_action',
                ('action_responsible_officer', 'action_responsible_email', 'action_due_date'),
                ('action_status', 'action_progress'),
                'action_last_update',
            ),
            'description': "Track the agreed treatment action, owner, deadline, and implementation progress.",
        }),
        ('Escalation', {
            'fields': ('escalation_status', 'escalation_reason', 'escalated_at'),
            'classes': ('collapse',),
            'description': "Critical residual risks and long-overdue actions are escalated automatically.",
        }),
        ('Residual Risk (After Controls)', {
            'fields': (('residual_probability', 'residual_impact', 'residual_rating'),),
            'description': "Select Probability and Impact.",
        }),
        ('Audit Trail', {
            'fields': ('updated_by', 'updated_at', 'created_at'),
            'classes': ('collapse',),
            'description': "System tracking information.",
        }),
    )

    def save_model(self, request, obj, form, change):
        obj.updated_by = request.user
        super().save_model(request, obj, form, change)
        SystemAuditLog.objects.create(
            user=request.user,
            action='update' if change else 'create',
            target_model='RiskAssessment',
            target_id=str(obj.pk),
            reference_id=obj.reference_id,
            area_name=obj.area_name or '',
            summary=(
                f"{'Updated' if change else 'Created'} risk {obj.reference_id} "
                f"for {obj.area_name or 'Unspecified'}."
            ),
            metadata={"changed_fields": list(form.changed_data)},
        )

    def delete_model(self, request, obj):
        reference_id = obj.reference_id
        area_name = obj.area_name or ''
        pk = obj.pk
        super().delete_model(request, obj)
        SystemAuditLog.objects.create(
            user=request.user,
            action='delete',
            target_model='RiskAssessment',
            target_id=str(pk),
            reference_id=reference_id,
            area_name=area_name,
            summary=f"Deleted risk {reference_id} from {area_name or 'Unspecified'}.",
            metadata={"source": "admin_single_delete"},
        )

    def delete_queryset(self, request, queryset):
        deleted_items = list(queryset.values('pk', 'reference_id', 'area_name'))
        count = len(deleted_items)
        super().delete_queryset(request, queryset)
        SystemAuditLog.objects.create(
            user=request.user,
            action='delete',
            target_model='RiskAssessment',
            summary=f"Bulk deleted {count} risk record(s) from admin.",
            metadata={"source": "admin_bulk_delete", "deleted_items": deleted_items},
        )

    # ====== COLORED BADGES ======
    def color_badge(self, rating):
        colors = {
            'Critical': '#d32f2f',
            'Severe': '#f57c00',
            'Moderate': '#fbc02d',
            'Sustainable': '#388e3c',
        }
        color = colors.get(rating, '#777')
        return format_html(
            '<div style="background-color:{}; color:white; padding:5px 10px; border-radius:4px; '
            'font-weight:bold; text-align:center; width:100px;">{}</div>',
            color, rating
        )

    def inherent_rating_colored(self, obj):
        return self.color_badge(obj.inherent_rating)
    inherent_rating_colored.short_description = "Inherent"
    inherent_rating_colored.admin_order_field = 'inherent_rating'

    def residual_rating_colored(self, obj):
        return self.color_badge(obj.residual_rating)
    residual_rating_colored.short_description = "Residual"
    residual_rating_colored.admin_order_field = 'residual_rating'

    def overdue_action_colored(self, obj):
        if obj.is_action_overdue:
            return format_html(
                '<div style="background-color:#d32f2f; color:white; padding:5px 10px; '
                'border-radius:4px; font-weight:bold; text-align:center;">{} day(s)</div>',
                obj.days_overdue
            )
        return format_html('<span style="color:{}; font-weight:bold;">No</span>', '#388e3c')
    overdue_action_colored.short_description = "Overdue"

    def short_description(self, obj):
        return obj.description[:40] + "..." if len(obj.description) > 40 else obj.description
    short_description.short_description = "Description"

    class Media:
        css = {'all': ('risks/admin_overrides.css',)}


@admin.register(RiskTrendSnapshot)
class RiskTrendSnapshotAdmin(admin.ModelAdmin):
    list_display = (
        'risk',
        'snapshot_date',
        'area_name',
        'inherent_rating',
        'residual_rating',
        'action_status',
        'action_progress',
        'created_at',
    )
    list_filter = ('snapshot_date', 'area_name', 'inherent_rating', 'residual_rating', 'action_status')
    search_fields = ('risk__reference_id', 'risk__description', 'area_name')
    readonly_fields = (
        'risk',
        'snapshot_date',
        'area_name',
        'inherent_probability',
        'inherent_impact',
        'inherent_rating',
        'residual_probability',
        'residual_impact',
        'residual_rating',
        'action_status',
        'action_progress',
        'created_at',
    )


@admin.register(AIAssistantAuditLog)
class AIAssistantAuditLogAdmin(admin.ModelAdmin):
    list_display = ('created_at', 'user', 'status', 'provider', 'model_name', 'used_live_llm', 'response_ms')
    list_filter = ('status', 'provider', 'used_live_llm', 'created_at')
    search_fields = ('question', 'answer', 'error_message')
    readonly_fields = (
        'user',
        'provider',
        'model_name',
        'question',
        'answer',
        'grounded_context',
        'citations',
        'used_live_llm',
        'status',
        'error_message',
        'response_ms',
        'created_at',
    )


@admin.register(SystemAuditLog)
class SystemAuditLogAdmin(admin.ModelAdmin):
    list_display = ('created_at', 'user', 'action', 'target_model', 'reference_id', 'area_name', 'summary')
    list_filter = ('action', 'target_model', 'area_name', 'created_at')
    search_fields = ('summary', 'reference_id', 'area_name', 'user__username')
    readonly_fields = (
        'user',
        'action',
        'target_model',
        'target_id',
        'reference_id',
        'area_name',
        'summary',
        'metadata',
        'created_at',
    )

    def has_add_permission(self, request):
        return False


@admin.register(CustomerRiskProfile)
class CustomerRiskProfileAdmin(admin.ModelAdmin):
    list_display = ('created_at', 'account_name', 'account_no', 'profile_rating', 'average_score', 'movement', 'next_review_date', 'risk')
    list_filter = ('profile_rating', 'movement', 'source_type', 'next_review_date', 'created_at')
    search_fields = ('account_name', 'account_no', 'profile_rating', 'risk__reference_id')
    readonly_fields = (
        'risk',
        'account_no',
        'account_name',
        'profile_rating',
        'average_score',
        'total_score',
        'determinant_count',
        'determinants',
        'recommendation',
        'enhanced_due_diligence',
        'confidence_notes',
        'source_filename',
        'source_type',
        'evidence_file',
        'review_frequency',
        'next_review_date',
        'previous_rating',
        'previous_average_score',
        'movement',
        'created_by',
        'created_at',
    )

    def has_add_permission(self, request):
        return False


@admin.register(RiskIncident)
class RiskIncidentAdmin(admin.ModelAdmin):
    list_display = ('incident_date', 'title', 'area_name', 'risk', 'loss_amount', 'status', 'reported_by', 'updated_at')
    list_filter = ('status', 'area_name', 'incident_date')
    search_fields = ('title', 'description', 'root_cause', 'risk__reference_id', 'area_name', 'reported_by')
    autocomplete_fields = ('risk',)
    fieldsets = (
        ('Incident Details', {
            'fields': ('risk', 'incident_date', 'area_name', 'title', 'description', 'root_cause'),
        }),
        ('Loss / Response', {
            'fields': ('loss_amount', 'status', 'reported_by', 'action_taken'),
        }),
    )


# ========= ADMIN SITE BRANDING =========
admin.site.site_header = "Bank Risk Management System"
admin.site.site_title = "Risk Admin Portal"
admin.site.index_title = "System Dashboard"
