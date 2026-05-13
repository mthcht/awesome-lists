rule Ransom_Win64_SorryRan_PA_2147969188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/SorryRan.PA!MTB"
        threat_id = "2147969188"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "SorryRan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = ".sorry" ascii //weight: 4
        $x_1_2 = "readme.md" ascii //weight: 1
        $x_1_3 = "desktop.ini" ascii //weight: 1
        $x_1_4 = "BEGIN PUBLIC KEY" ascii //weight: 1
        $x_1_5 = "RUST_BACKTRACE=full" ascii //weight: 1
        $x_1_6 = "-----BEGIN PUBLIC KEY-----" ascii //weight: 1
        $x_1_7 = "cmd.exe /e:ON /v:OFF /d /c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

