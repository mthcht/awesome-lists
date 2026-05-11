rule TrojanSpy_MSIL_SugarDump_A_2147969020_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/SugarDump.A!dha"
        threat_id = "2147969020"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SugarDump"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\"encrypted_key\":\"(.*?)\"" wide //weight: 1
        $x_1_2 = "password_value" wide //weight: 1
        $x_1_3 = "Opera Software\\Opera Stable" wide //weight: 1
        $x_1_4 = {6f 00 72 00 69 00 67 00 ?? 00 6e 00 5f 00 75 00 72 00 6c}  //weight: 1, accuracy: Low
        $x_1_5 = "\\Default\\Login Data" wide //weight: 1
        $x_1_6 = "passrecover.exe" ascii //weight: 1
        $x_1_7 = "=============================" wide //weight: 1
        $x_1_8 = "Application:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_SugarDump_B_2147969021_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/SugarDump.B!dha"
        threat_id = "2147969021"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SugarDump"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\"encrypted_key\":\"(.*?)\"" wide //weight: 1
        $x_1_2 = "password_value" wide //weight: 1
        $x_1_3 = "Opera Software\\Opera Stable" wide //weight: 1
        $x_1_4 = {6f 00 72 00 69 00 67 00 ?? 00 6e 00 5f 00 75 00 72 00 6c}  //weight: 1, accuracy: Low
        $x_1_5 = "\\Default\\Login Data" wide //weight: 1
        $x_1_6 = "<<<<<<<< ------ Passwords Total: {0} --------- >>>>>>>>" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_SugarDump_C_2147969022_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/SugarDump.C!dha"
        threat_id = "2147969022"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SugarDump"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\"encrypted_key\":\"(.*?)\"" wide //weight: 1
        $x_1_2 = "password_value" wide //weight: 1
        $x_1_3 = "Opera Software\\Opera Stable" wide //weight: 1
        $x_1_4 = {6f 00 72 00 69 00 67 00 ?? 00 6e 00 5f 00 75 00 72 00 6c}  //weight: 1, accuracy: Low
        $x_1_5 = "\\Default\\Login Data" wide //weight: 1
        $x_1_6 = "\\DebugLogWindowsDefender.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

