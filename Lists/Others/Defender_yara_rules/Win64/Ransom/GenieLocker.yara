rule Ransom_Win64_GenieLocker_YBE_2147965353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/GenieLocker.YBE!MTB"
        threat_id = "2147965353"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "GenieLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GenieLocker" ascii //weight: 1
        $x_1_2 = "genie_encrypt [options] [path]" ascii //weight: 1
        $x_1_3 = "Encryption percentage" ascii //weight: 1
        $x_1_4 = "will encrypt all drives" ascii //weight: 1
        $x_1_5 = "OLLYDBG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_GenieLocker_AMTB_2147970134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/GenieLocker!AMTB"
        threat_id = "2147970134"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "GenieLocker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GENIE LOCKER v%d Windows x64" ascii //weight: 1
        $x_1_2 = "genie_encrypt [options] [path]" ascii //weight: 1
        $x_1_3 = "Cannot open SCManager (need admin?)" ascii //weight: 1
        $x_1_4 = "encrypt only file header" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

