from django.contrib import admin

from .models import Command, Device, PairingCode


@admin.action(description="Revoke device token")
def revoke(modeladmin, request, queryset):
    queryset.update(revoked=True)


@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = ("name", "android_version", "app_version", "last_seen", "protection_on", "revoked")
    list_filter = ("revoked", "protection_on")
    search_fields = ("name",)
    actions = [revoke]
    readonly_fields = ("token_hash",)


@admin.register(PairingCode)
class PairingCodeAdmin(admin.ModelAdmin):
    list_display = ("code", "created_by", "created_at", "expires_at", "used_at")
    readonly_fields = ("code", "created_at", "expires_at", "used_at")


@admin.register(Command)
class CommandAdmin(admin.ModelAdmin):
    list_display = ("id", "device", "type", "created_at", "acked_at")
    list_filter = ("type",)
    readonly_fields = ("device", "type", "payload", "created_at", "acked_at")
