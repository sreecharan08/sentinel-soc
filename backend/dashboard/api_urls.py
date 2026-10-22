from django.urls import path

from remediation import dash_views as rem

from . import api, api_web

urlpatterns = [
    path("stats", api.StatsView.as_view()),
    path("events", api_web.EventsView.as_view()),
    path("network", api_web.NetworkView.as_view()),
    path("graph", api_web.GraphView.as_view()),
    path("pipeline", api_web.PipelineView.as_view()),
    path("remediation-queue", api_web.RemediationQueueView.as_view()),
    path("submissions", api.SubmissionListView.as_view()),
    path("submissions/<uuid:sid>", api.SubmissionDetailView.as_view()),
    path("submissions/<uuid:sid>/events", api.SubmissionEventsView.as_view()),
    path("submissions/<uuid:sid>/override", api.OverrideView.as_view()),
    path("submissions/<uuid:sid>/reanalyze", api.ReanalyzeView.as_view()),
    path("submissions/<uuid:sid>/remediation", rem.ProposeView.as_view()),
    path("submissions/<uuid:sid>/hold", rem.HoldView.as_view()),
    path("submissions/<uuid:sid>/generate-rules", api.GenerateRulesView.as_view()),
    path("remediations", rem.RemediationListView.as_view()),
    path("remediations/<uuid:rid>/cancel", rem.CancelView.as_view()),
    path("devices", api.DeviceListView.as_view()),
    path("pairing-code", api.PairingCodeView.as_view()),
    path("settings", api.SettingsView.as_view()),
    path("reputation", api.ReputationView.as_view()),
    path("rules", api.RuleListView.as_view()),
    path("rules/export", api.RulesExportView.as_view()),
    path("rules/<uuid:rid>", api.RuleDetailView.as_view()),
    path("rules/<uuid:rid>/approve", api.RuleApproveView.as_view()),
    path("rules/<uuid:rid>/retire", api.RuleRetireView.as_view()),
    path("rules/<uuid:rid>/validate", api.RuleValidateView.as_view()),
    path("rules/<uuid:rid>/fp-test", api.RuleFpTestView.as_view()),
    path("matches/<int:mid>/false-positive", api.MatchFalsePositiveView.as_view()),
    path("demo/preflight", api.DemoPreflightView.as_view()),
    path("demo/reset", api.DemoResetView.as_view()),
    path("demo/marker", api.DemoMarkerView.as_view()),
    path("demo/simulate", api.DemoSimulateView.as_view()),
    path("demo/fault", api.DemoFaultView.as_view()),
    path("demo/evidence-pack", api.EvidencePackView.as_view()),
    path("eval/latest", api.EvalLatestView.as_view()),
]
