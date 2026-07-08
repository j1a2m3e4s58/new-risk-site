from django.db import models
from django.utils import timezone
from django.conf import settings
from datetime import timedelta


class RiskAssessment(models.Model):
    # --- DROPDOWN CHOICES ---
    PROBABILITY_CHOICES = [
        ('Very High', 'Very High'),
        ('High', 'High'),
        ('Medium', 'Moderate'),
        ('Low', 'Low'),
        ('Very Low', 'Very Low'),
    ]

    IMPACT_CHOICES = [
        ('Very High', 'Very High'),
        ('High', 'High'),
        ('Medium', 'Moderate'),
        ('Low', 'Low'),
        ('Very Low', 'Very Low'),
    ]

    RATING_CHOICES = [
        ('Critical', 'Critical'),
        ('Severe', 'Severe'),
        ('Moderate', 'Moderate'),
        ('Sustainable', 'Sustainable'),
    ]

    ACTION_STATUS_CHOICES = [
        ('Not Started', 'Not Started'),
        ('In Progress', 'In Progress'),
        ('Completed', 'Completed'),
        ('Deferred', 'Deferred'),
    ]

    WORKFLOW_STATUS_CHOICES = [
        ('Draft', 'Draft'),
        ('Reviewed', 'Reviewed'),
        ('Approved', 'Approved'),
        ('Closed', 'Closed'),
    ]

    ESCALATION_STATUS_CHOICES = [
        ('Normal', 'Normal'),
        ('Management Attention', 'Management Attention'),
        ('Board Attention', 'Board Attention'),
    ]

    CONTROL_EFFECTIVENESS_CHOICES = [
        ('Not Assessed', 'Not Assessed'),
        ('Strong', 'Strong'),
        ('Moderate', 'Moderate'),
        ('Weak', 'Weak'),
    ]

    # --- IDENTIFICATION ---
    reference_id = models.CharField(max_length=20, unique=True, help_text="Unique ID (e.g., RISK-001)")
    area_name = models.CharField(max_length=100, blank=True, null=True, help_text="Department or Area (e.g. IT, Finance)")
    description = models.TextField(verbose_name="Risk Description")

    # --- NEW SEPARATE FIELDS ---
    caused_by = models.TextField(verbose_name="Root Cause", blank=True, default="", help_text="What triggers this risk?")
    consequences = models.TextField(verbose_name="Consequences", blank=True, default="", help_text="What happens if this risk occurs?")
    customer_profile_score = models.DecimalField(max_digits=4, decimal_places=2, blank=True, null=True)
    customer_profile_rating = models.CharField(max_length=20, blank=True, default="")
    customer_profile_notes = models.TextField(blank=True, default="")

    risk_owner = models.CharField(max_length=100, help_text="Person responsible for this risk")
    workflow_status = models.CharField(
        max_length=20,
        choices=WORKFLOW_STATUS_CHOICES,
        default='Approved',
        help_text="Approval stage for this risk record.",
    )

    # ========= RISK_COORDINATOR_FIELD_START =========
    risk_coordinator = models.CharField(
        max_length=100,
        blank=True,
        default="",
        help_text="Coordinator for monitoring / reporting"
    )
    # ========= RISK_COORDINATOR_FIELD_END =========

    # ========= RISK_COORDINATOR_NAME_FIELD_START =========
    risk_coordinator_name = models.CharField(
        max_length=100,
        blank=True,
        default="",
        help_text="Coordinator responsible for follow-up / reporting"
    )
    # ========= RISK_COORDINATOR_NAME_FIELD_END =========



    # --- INHERENT RISK (Before Controls) ---
    inherent_probability = models.CharField(max_length=20, choices=PROBABILITY_CHOICES)
    inherent_impact = models.CharField(max_length=20, choices=IMPACT_CHOICES)
    inherent_rating = models.CharField(max_length=20, choices=RATING_CHOICES, blank=True, editable=False)

    # --- CONTROLS ---
    controls = models.TextField(verbose_name="Control Descriptions", blank=True)
    control_owner = models.CharField(max_length=100, blank=True)
    control_effectiveness = models.CharField(
        max_length=20,
        choices=CONTROL_EFFECTIVENESS_CHOICES,
        default='Not Assessed',
    )
    control_effectiveness_rationale = models.TextField(blank=True, default="")

    # --- ACTION PLAN ---
    mitigation_action = models.TextField(
        verbose_name="Mitigation Action Plan",
        blank=True,
        default="",
        help_text="Specific action management will take to reduce or control this risk.",
    )
    action_responsible_officer = models.CharField(
        max_length=100,
        blank=True,
        default="",
        help_text="Officer responsible for completing the mitigation action.",
    )
    action_responsible_email = models.EmailField(
        blank=True,
        default="",
        help_text="Email address for due-date and overdue action reminders.",
    )
    action_due_date = models.DateField(
        blank=True,
        null=True,
        help_text="Target completion date for the mitigation action.",
    )
    action_status = models.CharField(
        max_length=20,
        choices=ACTION_STATUS_CHOICES,
        default='Not Started',
    )
    action_progress = models.PositiveSmallIntegerField(
        default=0,
        help_text="Completion progress from 0 to 100 percent.",
    )
    action_last_update = models.TextField(
        verbose_name="Action Progress Update",
        blank=True,
        default="",
        help_text="Latest management update on the action plan.",
    )

    # --- ESCALATION ---
    escalation_status = models.CharField(
        max_length=30,
        choices=ESCALATION_STATUS_CHOICES,
        default='Normal',
    )
    escalation_reason = models.TextField(blank=True, default="")
    escalated_at = models.DateTimeField(blank=True, null=True)

    # --- RESIDUAL RISK (After Controls) ---
    residual_probability = models.CharField(max_length=20, choices=PROBABILITY_CHOICES)
    residual_impact = models.CharField(max_length=20, choices=IMPACT_CHOICES)
    residual_rating = models.CharField(max_length=20, choices=RATING_CHOICES, blank=True, editable=False)

    # --- AUDIT TRAIL ---
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='risks_updated'
    )

    def calculate_rating(self, prob, impact):
        """Standard 5x5 Matrix Logic"""
        # 1. Critical (Red)
        if (prob == 'Very High' and impact in ['Very High', 'High', 'Medium']) or \
           (prob == 'High' and impact in ['Very High', 'High']) or \
           (prob == 'Medium' and impact == 'Very High'):
            return 'Critical'

        # 2. Severe (Orange)
        if (prob == 'Very High' and impact == 'Low') or \
           (prob == 'High' and impact == 'Medium') or \
           (prob == 'Medium' and impact == 'High') or \
           (prob == 'Low' and impact == 'Very High'):
            return 'Severe'

        # 3. Moderate (Yellow)
        if (prob == 'Very High' and impact == 'Very Low') or \
           (prob == 'High' and impact == 'Low') or \
           (prob == 'Medium' and impact in ['Medium', 'Low']) or \
           (prob == 'Low' and impact in ['High', 'Medium']) or \
           (prob == 'Very Low' and impact in ['Very High', 'High']):
            return 'Moderate'

        # 4. Sustainable (Green)
        return 'Sustainable'

    def save(self, *args, **kwargs):
        self.inherent_rating = self.calculate_rating(self.inherent_probability, self.inherent_impact)
        self.residual_rating = self.calculate_rating(self.residual_probability, self.residual_impact)
        self.action_progress = max(0, min(int(self.action_progress or 0), 100))
        self.apply_auto_escalation()
        super().save(*args, **kwargs)
        if not getattr(self, "_skip_trend_snapshot", False):
            RiskTrendSnapshot.record_for_risk(self)

    @property
    def is_action_overdue(self):
        if not self.action_due_date or self.action_status == 'Completed':
            return False
        return self.action_due_date < timezone.localdate()

    @property
    def days_overdue(self):
        if not self.is_action_overdue:
            return 0
        return (timezone.localdate() - self.action_due_date).days

    @property
    def residual_trend_label(self):
        snapshots = list(self.trend_snapshots.order_by('-snapshot_date')[:2])
        if len(snapshots) < 2:
            return "New"

        rank = {"Sustainable": 1, "Moderate": 2, "Severe": 3, "Critical": 4}
        current = rank.get(snapshots[0].residual_rating, 0)
        previous = rank.get(snapshots[1].residual_rating, 0)

        if current < previous:
            return "Improving"
        if current > previous:
            return "Worsening"
        return "Stable"

    def apply_auto_escalation(self):
        previous_status = self.escalation_status
        reason = ""

        if self.workflow_status == 'Closed' or self.action_status == 'Completed':
            self.escalation_status = 'Normal'
            self.escalation_reason = ""
            self.escalated_at = None
            return

        if self.residual_rating == 'Critical':
            self.escalation_status = 'Board Attention'
            reason = "Critical residual risk requires board attention."
        elif self.action_due_date and self.action_due_date < timezone.localdate() - timedelta(days=7):
            self.escalation_status = 'Management Attention'
            reason = "Mitigation action is more than 7 days overdue."

        if reason:
            self.escalation_reason = reason
            if previous_status == 'Normal' or not self.escalated_at:
                self.escalated_at = timezone.now()
        elif self.escalation_status != 'Board Attention':
            self.escalation_status = 'Normal'
            self.escalation_reason = ""
            self.escalated_at = None

        # ========= AUTO_FILL_PROPERTIES_START =========
    @property
    def control_description(self):
        # official_report.html expects this name
        return self.controls or "Standard Controls"

    @property
    def risk_coordinator(self):
        # official_report.html expects this name
        return self.risk_coordinator_name or "-"
    # ========= AUTO_FILL_PROPERTIES_END =========


    def __str__(self):
        return f"{self.reference_id} - {self.description[:30]}"


class RiskTrendSnapshot(models.Model):
    risk = models.ForeignKey(
        RiskAssessment,
        on_delete=models.CASCADE,
        related_name='trend_snapshots',
    )
    snapshot_date = models.DateField(default=timezone.localdate)
    area_name = models.CharField(max_length=100, blank=True, default="")
    inherent_probability = models.CharField(max_length=20)
    inherent_impact = models.CharField(max_length=20)
    inherent_rating = models.CharField(max_length=20)
    residual_probability = models.CharField(max_length=20)
    residual_impact = models.CharField(max_length=20)
    residual_rating = models.CharField(max_length=20)
    action_status = models.CharField(max_length=20, blank=True, default="")
    action_progress = models.PositiveSmallIntegerField(default=0)
    notes = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-snapshot_date', 'risk__reference_id']
        unique_together = ('risk', 'snapshot_date')
        verbose_name = "Risk Trend Snapshot"
        verbose_name_plural = "Risk Trend Snapshots"

    @classmethod
    def record_for_risk(cls, risk):
        cls.objects.update_or_create(
            risk=risk,
            snapshot_date=timezone.localdate(),
            defaults={
                'area_name': risk.area_name or "",
                'inherent_probability': risk.inherent_probability,
                'inherent_impact': risk.inherent_impact,
                'inherent_rating': risk.inherent_rating,
                'residual_probability': risk.residual_probability,
                'residual_impact': risk.residual_impact,
                'residual_rating': risk.residual_rating,
                'action_status': risk.action_status,
                'action_progress': risk.action_progress,
            },
        )

    def __str__(self):
        return f"{self.risk.reference_id} trend on {self.snapshot_date}"


class SystemAuditLog(models.Model):
    ACTION_CHOICES = [
        ('create', 'Create'),
        ('update', 'Update'),
        ('delete', 'Delete'),
        ('export', 'Export'),
        ('approve', 'Approve'),
        ('login', 'Login'),
        ('other', 'Other'),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='system_audit_logs',
    )
    action = models.CharField(max_length=20, choices=ACTION_CHOICES, default='other')
    target_model = models.CharField(max_length=100, blank=True, default='')
    target_id = models.CharField(max_length=100, blank=True, default='')
    reference_id = models.CharField(max_length=100, blank=True, default='')
    area_name = models.CharField(max_length=100, blank=True, default='')
    summary = models.TextField(blank=True, default='')
    metadata = models.JSONField(blank=True, default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = "System Audit Log"
        verbose_name_plural = "System Audit Logs"

    def __str__(self):
        return f"{self.action} - {self.summary[:60]}"


class RiskIncident(models.Model):
    INCIDENT_STATUS_CHOICES = [
        ('Open', 'Open'),
        ('Investigating', 'Investigating'),
        ('Resolved', 'Resolved'),
        ('Closed', 'Closed'),
    ]

    risk = models.ForeignKey(
        RiskAssessment,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='incidents',
    )
    incident_date = models.DateField(default=timezone.localdate)
    area_name = models.CharField(max_length=100, blank=True, default="")
    title = models.CharField(max_length=200)
    description = models.TextField()
    root_cause = models.TextField(blank=True, default="")
    loss_amount = models.DecimalField(max_digits=14, decimal_places=2, default=0)
    status = models.CharField(max_length=20, choices=INCIDENT_STATUS_CHOICES, default='Open')
    reported_by = models.CharField(max_length=100, blank=True, default="")
    action_taken = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-incident_date', '-created_at']
        verbose_name = "Loss / Incident"
        verbose_name_plural = "Loss / Incident Register"

    def save(self, *args, **kwargs):
        if self.risk and not self.area_name:
            self.area_name = self.risk.area_name or ""
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.incident_date} - {self.title}"


# --- NEW REPORT CONFIGURATION MODEL ---
class ReportConfiguration(models.Model):
    """Stores the editable text for the Official Report"""
    executive_summary = models.TextField(default="This document contains the official record of identified operational and financial risks.")
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return "Official Report Settings"

    class Meta:
        # This creates the specific permission we need: 'risks.view_reportconfiguration'
        verbose_name = "Report Settings"


# ========= AI_SETTINGS_START =========
class AISettings(models.Model):
    enable_ai = models.BooleanField(default=False)
    provider = models.CharField(max_length=30, default='openai')
    model_name = models.CharField(max_length=100, default='gpt-4.1-mini')
    max_context_risks = models.PositiveIntegerField(default=12)
    system_prompt = models.TextField(
        default=(
            "You are a bank compliance copilot. Answer only from the grounded system context provided. "
            "Do not invent facts, do not claim to have checked records that are not in the context, "
            "and make your uncertainty explicit whenever the system data is incomplete."
        )
    )
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return "AI Settings"
# ========= AI_SETTINGS_END =========


class AIAssistantAuditLog(models.Model):
    STATUS_CHOICES = [
        ('success', 'Success'),
        ('fallback', 'Fallback'),
        ('error', 'Error'),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='ai_assistant_logs',
    )
    provider = models.CharField(max_length=30, default='openai')
    model_name = models.CharField(max_length=100, blank=True, default='')
    question = models.TextField()
    answer = models.TextField(blank=True, default='')
    grounded_context = models.JSONField(blank=True, default=dict)
    citations = models.JSONField(blank=True, default=list)
    used_live_llm = models.BooleanField(default=False)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='fallback')
    error_message = models.TextField(blank=True, default='')
    response_ms = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = 'AI Assistant Audit Log'
        verbose_name_plural = 'AI Assistant Audit Logs'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.status} - {self.question[:50]}"
