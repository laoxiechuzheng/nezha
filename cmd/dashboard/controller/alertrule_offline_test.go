package controller

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/service/singleton"
)

func applyOfflineAlertRuleForm(rule *model.AlertRule, form model.AlertRuleForm) {
	enable := form.Enable
	rule.Name = form.Name
	rule.Rules = form.Rules
	rule.FailTriggerTasks = form.FailTriggerTasks
	rule.RecoverTriggerTasks = form.RecoverTriggerTasks
	rule.NotificationGroupID = form.NotificationGroupID
	rule.TriggerMode = form.TriggerMode
	rule.Enable = &enable
}

func TestAlertRuleOfflineDurationValidationAndPersistenceRoundTrip(t *testing.T) {
	setupAlertRuleFanoutFixture(t)

	viewer := &model.User{Common: model.Common{ID: 1}, Role: model.RoleAdmin}
	form := func(duration uint64) map[string]any {
		return map[string]any{
			"name":                  "offline-duration-persistence",
			"enable":                false,
			"notification_group_id": 0,
			"rules": []map[string]any{{
				"type":     "offline",
				"cover":    model.RuleCoverIgnoreAll,
				"duration": duration,
				"ignore":   map[uint64]bool{2: true, 3: false},
			}},
		}
	}

	createCtx := newAlertRuleCtxWithPAT(t, viewer, nil, form(30))
	var createForm model.AlertRuleForm
	require.NoError(t, createCtx.ShouldBindJSON(&createForm))
	created := &model.AlertRule{Common: model.Common{UserID: 1}}
	applyOfflineAlertRuleForm(created, createForm)
	require.NoError(t, validateRule(createCtx, created))
	require.NoError(t, singleton.DB.Create(created).Error)

	var loaded model.AlertRule
	require.NoError(t, singleton.DB.First(&loaded, created.ID).Error)
	require.Len(t, loaded.Rules, 1)
	require.Equal(t, uint64(30), loaded.Rules[0].Duration)
	require.Equal(t, uint64(model.RuleCoverIgnoreAll), loaded.Rules[0].Cover)
	require.Equal(t, map[uint64]bool{2: true, 3: false}, loaded.Rules[0].Ignore)

	updateCtx := newAlertRuleCtxWithPAT(t, viewer, nil, form(10))
	var updateForm model.AlertRuleForm
	require.NoError(t, updateCtx.ShouldBindJSON(&updateForm))
	applyOfflineAlertRuleForm(&loaded, updateForm)
	require.NoError(t, validateRule(updateCtx, &loaded))
	require.NoError(t, singleton.DB.Save(&loaded).Error)

	var updated model.AlertRule
	require.NoError(t, singleton.DB.First(&updated, created.ID).Error)
	require.Len(t, updated.Rules, 1)
	require.Equal(t, uint64(10), updated.Rules[0].Duration)
	require.Equal(t, uint64(model.RuleCoverIgnoreAll), updated.Rules[0].Cover)
	require.Equal(t, map[uint64]bool{2: true, 3: false}, updated.Rules[0].Ignore)
}
