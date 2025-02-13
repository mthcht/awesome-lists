rule TrojanSpy_MSIL_Smets_A_2147653846_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Smets.gen!A"
        threat_id = "2147653846"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Smets"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Website: {0} {3}Username: {1} {3}Password:{2}" wide //weight: 10
        $x_1_2 = "encryptedPassword" wide //weight: 1
        $x_1_3 = "mozsqlite3" ascii //weight: 1
        $x_1_4 = "user32:SetWindowsHookEx" wide //weight: 1
        $x_1_5 = "user32:CallNextHookEx" wide //weight: 1
        $x_1_6 = "user32:UnhookWindowsHookEx" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

