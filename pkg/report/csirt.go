// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package report

import (
	"fmt"
	"strings"
)

// csirtTable maps ISO 3166-1 alpha-2 country codes to CSIRT coordinator names.
// Source: ENISA CSIRT-network member list (https://csirtsnetwork.eu)
// Last verified: 2026-04-04
//
// This is informational metadata only. Per Art. 14(7), notifications are
// submitted via the ENISA Single Reporting Platform (Art. 16), NOT directly
// to the CSIRT.
var csirtTable = map[string]string{
	// EU Member States (27)
	"AT": "CERT.at",
	"BE": "CERT.be (Centre for Cybersecurity Belgium)",
	"BG": "CERT Bulgaria",
	"HR": "CERT.hr (CARNET CERT)",
	"CY": "CSIRT-CY (Digital Security Authority)",
	"CZ": "CSIRT.CZ (CZ.NIC)",
	"DK": "CFCS (Centre for Cyber Security)",
	"EE": "CERT-EE (RIA)",
	"FI": "NCSC-FI (Traficom)",
	"FR": "CERT-FR (ANSSI)",
	"DE": "BSI (CERT-Bund)",
	"GR": "GR-CSIRT (National CSIRT Greece)",
	"HU": "NCSC-HU (NBSZ)",
	"IE": "CSIRT-IE (NCSC Ireland)",
	"IT": "CSIRT Italia (ACN)",
	"LV": "CERT.LV",
	"LT": "CERT-LT (NRD CSIRT)",
	"LU": "CIRCL (CSIRT Luxembourg)",
	"MT": "CSIRTMalta (MITA)",
	"NL": "NCSC-NL",
	"PL": "CERT Polska (NASK)",
	"PT": "CERT.PT (CNCS)",
	"RO": "CERT-RO",
	"SK": "SK-CERT (NSA SR)",
	"SI": "SI-CERT (ARNES)",
	"ES": "CCN-CERT (CNI)",
	"SE": "CERT-SE (MSB)",
	// EEA Members (3)
	"NO": "NorCERT (NSM)",
	"IS": "CERT-IS (ISNIC)",
	"LI": "CERT Liechtenstein (AMS)",
}

// LookupCSIRT returns the CSIRT coordinator info for the given country code.
// Country codes are case-insensitive.
func LookupCSIRT(countryCode string) (CSIRTInfo, error) {
	code := strings.ToUpper(countryCode)
	name, ok := csirtTable[code]
	if !ok {
		return CSIRTInfo{}, fmt.Errorf("report: no CSIRT coordinator found for country code %q", code)
	}
	return CSIRTInfo{
		Name:              name,
		Country:           code,
		SubmissionChannel: SubmissionChannelENISA,
	}, nil
}
