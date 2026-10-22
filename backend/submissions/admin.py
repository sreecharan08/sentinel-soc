from django.contrib import admin

from pipeline.models import PipelineEvent

from .models import AnalystAction, Sample, Submission, Verdict


class EventInline(admin.TabularInline):
    model = PipelineEvent
    extra = 0
    can_delete = False
    fields = ("ts", "stage", "step", "level", "message")
    readonly_fields = fields
    ordering = ("-id",)
    max_num = 50

    def has_add_permission(self, request, obj=None):
        return False


@admin.register(Submission)
class SubmissionAdmin(admin.ModelAdmin):
    list_display = ("id", "package_name", "status", "device", "created_at")
    list_filter = ("status", "device")
    search_fields = ("package_name", "id")
    readonly_fields = ("id", "created_at", "updated_at")
    inlines = [EventInline]
    actions = ["requeue"]

    @admin.action(description="Re-queue selected submissions")
    def requeue(self, request, queryset):
        from pipeline.tasks import enqueue_pipeline

        for sub in queryset.filter(status__in=["verdict_ready", "error"]):
            sub.status = "queued"
            sub.save(update_fields=["status"])
            enqueue_pipeline(sub.id)


@admin.register(Sample)
class SampleAdmin(admin.ModelAdmin):
    list_display = ("sha256", "size_bytes", "first_seen")
    search_fields = ("sha256",)
    readonly_fields = ("file_path",)


@admin.register(Verdict)
class VerdictAdmin(admin.ModelAdmin):
    list_display = ("submission", "label", "confidence", "provider_name", "is_current")
    list_filter = ("label", "provider_name")
    search_fields = ("submission__package_name",)
    readonly_fields = ("payload",)


@admin.register(AnalystAction)
class AnalystActionAdmin(admin.ModelAdmin):
    list_display = ("submission", "kind", "from_label", "to_label", "user", "created_at")
    readonly_fields = [f.name for f in AnalystAction._meta.fields]
