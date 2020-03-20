package sync

import "go-yubikey-val/internal/database"

func CountersEqual(p1, p2 database.Params) bool {
	return (p1.SessionCounter == p2.SessionCounter && p1.UseCounter == p2.UseCounter)
}

func CountersHigherThan(p1, p2 database.Params) bool {
	if p1.SessionCounter > p2.SessionCounter {
		return true
	}
	if p1.SessionCounter == p2.SessionCounter && p1.UseCounter > p2.UseCounter {
		return true
	}
	return false
}

func CountersHigherThanOrEqual(p1, p2 database.Params) bool {
	if p1.SessionCounter > p2.SessionCounter {
		return true
	}
	if p1.SessionCounter == p2.SessionCounter && p1.UseCounter >= p2.UseCounter {
		return true
	}
	return false
}

func UpdateDbCounters(params database.Params) bool {
	if params.PublicName == "" {
		return false
	}
	return database.UpdateDbCounters(params.YubiKey)
}
