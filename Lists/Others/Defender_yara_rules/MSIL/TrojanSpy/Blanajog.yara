rule TrojanSpy_MSIL_Blanajog_A_2147688657_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Blanajog.A"
        threat_id = "2147688657"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blanajog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "njLogger" ascii //weight: 1
        $x_1_2 = {00 4c 61 73 74 41 56 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 4c 61 73 74 41 53 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 57 52 4b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Blanajog_A_2147688657_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Blanajog.A"
        threat_id = "2147688657"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blanajog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "43"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "njLogger" ascii //weight: 10
        $x_10_2 = "GetAsyncKeyState" ascii //weight: 10
        $x_10_3 = "KBDLLHOOKSTRUCT" ascii //weight: 10
        $x_10_4 = "CallNextHookEx" ascii //weight: 10
        $x_1_5 = {4c 61 73 74 41 56 00}  //weight: 1, accuracy: High
        $x_1_6 = {4c 61 73 74 41 53 00}  //weight: 1, accuracy: High
        $x_1_7 = {57 52 4b 00}  //weight: 1, accuracy: High
        $x_1_8 = "[ENTER]" wide //weight: 1
        $x_1_9 = "[TAP]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_MSIL_Blanajog_B_2147688658_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Blanajog.B"
        threat_id = "2147688658"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blanajog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "njLogger" ascii //weight: 1
        $x_1_2 = "LastAV" ascii //weight: 1
        $x_1_3 = "openkl" wide //weight: 1
        $x_1_4 = "getlogs" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

