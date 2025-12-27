rule Ransom_Win64_NitrogenCrypt_PA_2147945661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/NitrogenCrypt.PA!MTB"
        threat_id = "2147945661"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "NitrogenCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Nitrogen welcome you!" ascii //weight: 5
        $x_1_2 = "_READ_ME_.TXT" ascii //weight: 1
        $x_2_3 = "/c vssadmin.exe delete shadows /all /quiet" wide //weight: 2
        $x_1_4 = "readme.txt" wide //weight: 1
        $x_1_5 = "cmd /c taskkill /im %ls /f" wide //weight: 1
        $x_1_6 = "bcdedit /deletevalue {default} safeboot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

