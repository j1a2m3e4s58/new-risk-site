from datetime import timedelta

from django.conf import settings
from django.core.mail import send_mail
from django.core.management.base import BaseCommand
from django.utils import timezone

from risks.models import RiskAssessment, SystemAuditLog


class Command(BaseCommand):
    help = "Send due-soon and overdue risk action reminders."

    def add_arguments(self, parser):
        parser.add_argument(
            "--due-days",
            type=int,
            default=3,
            help="Send reminders for actions due within this many days.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show who would be emailed without sending messages.",
        )

    def handle(self, *args, **options):
        due_days = options["due_days"]
        dry_run = options["dry_run"]
        today = timezone.localdate()
        due_limit = today + timedelta(days=due_days)

        risks = (
            RiskAssessment.objects.exclude(action_status="Completed")
            .exclude(action_responsible_email__exact="")
            .exclude(action_due_date__isnull=True)
            .filter(action_due_date__lte=due_limit)
            .order_by("action_due_date", "reference_id")
        )

        sent_count = 0
        for risk in risks:
            overdue_text = (
                f"{risk.days_overdue} day(s) overdue"
                if risk.is_action_overdue
                else f"due on {risk.action_due_date}"
            )
            subject = f"Risk action reminder: {risk.reference_id} is {overdue_text}"
            message = (
                f"Risk: {risk.reference_id}\n"
                f"Department: {risk.area_name or 'Unspecified'}\n"
                f"Responsible Officer: {risk.action_responsible_officer or '-'}\n"
                f"Status: {risk.action_status}\n"
                f"Progress: {risk.action_progress}%\n"
                f"Due Date: {risk.action_due_date}\n\n"
                f"Action Plan:\n{risk.mitigation_action or 'No action plan recorded.'}\n"
            )

            if dry_run:
                self.stdout.write(f"DRY RUN: {risk.action_responsible_email} <- {subject}")
            else:
                send_mail(
                    subject,
                    message,
                    getattr(settings, "DEFAULT_FROM_EMAIL", "risk-system@localhost"),
                    [risk.action_responsible_email],
                    fail_silently=False,
                )
                sent_count += 1

        if not dry_run:
            SystemAuditLog.objects.create(
                action="other",
                target_model="RiskAssessment",
                summary=f"Sent {sent_count} risk action reminder email(s).",
                metadata={"due_days": due_days},
            )

        self.stdout.write(self.style.SUCCESS(f"Processed {risks.count()} reminder candidate(s)."))
