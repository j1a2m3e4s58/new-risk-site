from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('risks', '0014_riskassessment_action_responsible_email'),
    ]

    operations = [
        migrations.AlterField(
            model_name='riskassessment',
            name='inherent_impact',
            field=models.CharField(choices=[('Very High', 'Very High'), ('High', 'High'), ('Medium', 'Moderate'), ('Low', 'Low'), ('Very Low', 'Very Low')], max_length=20),
        ),
        migrations.AlterField(
            model_name='riskassessment',
            name='inherent_probability',
            field=models.CharField(choices=[('Very High', 'Very High'), ('High', 'High'), ('Medium', 'Moderate'), ('Low', 'Low'), ('Very Low', 'Very Low')], max_length=20),
        ),
        migrations.AlterField(
            model_name='riskassessment',
            name='residual_impact',
            field=models.CharField(choices=[('Very High', 'Very High'), ('High', 'High'), ('Medium', 'Moderate'), ('Low', 'Low'), ('Very Low', 'Very Low')], max_length=20),
        ),
        migrations.AlterField(
            model_name='riskassessment',
            name='residual_probability',
            field=models.CharField(choices=[('Very High', 'Very High'), ('High', 'High'), ('Medium', 'Moderate'), ('Low', 'Low'), ('Very Low', 'Very Low')], max_length=20),
        ),
    ]
