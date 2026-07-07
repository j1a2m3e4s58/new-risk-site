from django import forms

from .models import RiskAssessment, RiskIncident


class RiskAssessmentForm(forms.ModelForm):
    class Meta:
        model = RiskAssessment
        fields = [
            "reference_id",
            "area_name",
            "description",
            "caused_by",
            "consequences",
            "risk_owner",
            "risk_coordinator_name",
            "workflow_status",
            "inherent_probability",
            "inherent_impact",
            "controls",
            "control_owner",
            "control_effectiveness",
            "control_effectiveness_rationale",
            "mitigation_action",
            "action_responsible_officer",
            "action_responsible_email",
            "action_due_date",
            "action_status",
            "action_progress",
            "action_last_update",
            "residual_probability",
            "residual_impact",
        ]
        widgets = {
            "description": forms.Textarea(attrs={"rows": 4}),
            "caused_by": forms.Textarea(attrs={"rows": 3}),
            "consequences": forms.Textarea(attrs={"rows": 3}),
            "controls": forms.Textarea(attrs={"rows": 3}),
            "control_effectiveness_rationale": forms.Textarea(attrs={"rows": 3}),
            "mitigation_action": forms.Textarea(attrs={"rows": 3}),
            "action_last_update": forms.Textarea(attrs={"rows": 3}),
            "action_due_date": forms.DateInput(attrs={"type": "date"}),
            "action_progress": forms.NumberInput(attrs={"min": 0, "max": 100}),
        }


class RiskActionUpdateForm(forms.ModelForm):
    class Meta:
        model = RiskAssessment
        fields = [
            "mitigation_action",
            "action_responsible_officer",
            "action_responsible_email",
            "action_due_date",
            "action_status",
            "action_progress",
            "action_last_update",
        ]
        widgets = {
            "mitigation_action": forms.Textarea(attrs={"rows": 3}),
            "action_due_date": forms.DateInput(attrs={"type": "date"}),
            "action_progress": forms.NumberInput(attrs={"min": 0, "max": 100}),
            "action_last_update": forms.Textarea(attrs={"rows": 4}),
        }


class RiskIncidentForm(forms.ModelForm):
    class Meta:
        model = RiskIncident
        fields = [
            "risk",
            "incident_date",
            "area_name",
            "title",
            "description",
            "root_cause",
            "loss_amount",
            "status",
            "reported_by",
            "action_taken",
        ]
        widgets = {
            "incident_date": forms.DateInput(attrs={"type": "date"}),
            "description": forms.Textarea(attrs={"rows": 3}),
            "root_cause": forms.Textarea(attrs={"rows": 3}),
            "action_taken": forms.Textarea(attrs={"rows": 3}),
        }
