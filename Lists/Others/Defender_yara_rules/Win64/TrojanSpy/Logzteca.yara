rule TrojanSpy_Win64_Logzteca_A_2147690323_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win64/Logzteca.A"
        threat_id = "2147690323"
        type = "TrojanSpy"
        platform = "Win64: Windows 64-bit platform"
        family = "Logzteca"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {b9 61 65 72 43 ff 15 ?? ?? 00 00 b9 65 52 65 74 89 44 24 40 ff 15 ?? ?? 00 00 b9 65 74 6f 6d}  //weight: 4, accuracy: Low
        $x_2_2 = {48 bf 32 a2 df 2d 99 2b 00 00 48 3b c7 74 0c 48 f7 d0}  //weight: 2, accuracy: High
        $x_1_3 = "GET /Photos/Query.cgi?loginid=" ascii //weight: 1
        $x_1_4 = "Elevation:Administrator!new:{3ad05575" wide //weight: 1
        $x_1_5 = "icacls \"%s\" /grant everyone:(f)" wide //weight: 1
        $x_1_6 = "root%\\System32\\msaud" wide //weight: 1
        $x_1_7 = "bcdedit -set recoveryenabled 0" wide //weight: 1
        $x_1_8 = "icacls \"%s\" /setowner \"NT ServiceTrustedInstaller\"" wide //weight: 1
        $x_1_9 = {c7 44 24 20 78 45 00 00 ba 74 72 69 56 41 b9 63 6f 6c 6c 41 b8 41 6c 61 75}  //weight: 1, accuracy: High
        $x_1_10 = {41 bc 65 74 6e 49 48 8d 4c 24 70 41 8b d4 41 b9 6e 65 70 4f 41 b8 74 65 6e 72}  //weight: 1, accuracy: High
        $x_1_11 = "POST /Catelog/login1.cgi" ascii //weight: 1
        $x_1_12 = "GET HTTP://%s:%d/Photos/Query.cgi?loginid=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_4_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

