rule Trojan_Win64_ArcaneStealer_ARC_2147964563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ArcaneStealer.ARC!MTB"
        threat_id = "2147964563"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ArcaneStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "arcanepanel.cc" ascii //weight: 3
        $x_1_2 = "Brute.txt" ascii //weight: 1
        $x_1_3 = "arcane_boundary" ascii //weight: 1
        $x_1_4 = "ArcaneUploader/1.0" wide //weight: 1
        $x_1_5 = "Arcane/1.0" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ArcaneStealer_ATC_2147964565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ArcaneStealer.ATC!MTB"
        threat_id = "2147964565"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ArcaneStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Arcane Grabber module loaded" ascii //weight: 1
        $x_1_2 = "Already running as admin, starting directly" ascii //weight: 1
        $x_1_3 = "Not admin, attempting elevation via rundll32" ascii //weight: 1
        $x_1_4 = "Elevated instance completed successfully" ascii //weight: 1
        $x_1_5 = "Starting collection" ascii //weight: 1
        $x_1_6 = "Killing target processes" ascii //weight: 1
        $x_1_7 = "Fetching IP info" ascii //weight: 1
        $x_1_8 = "Upload SUCCESS" ascii //weight: 1
        $x_1_9 = "Upload FAILED after 5 attempts" ascii //weight: 1
        $x_1_10 = "grabber_boundary" ascii //weight: 1
        $x_1_11 = "dLoaderGrabber/1.0" wide //weight: 1
        $x_1_12 = "Arcane/1.0" wide //weight: 1
        $x_1_13 = "arcane_le" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ArcaneStealer_MX_2147965167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ArcaneStealer.MX!MTB"
        threat_id = "2147965167"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ArcaneStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "arcanepanel.cc" ascii //weight: 1
        $x_1_2 = "ArcaneUploader/1.0" wide //weight: 1
        $x_1_3 = "Cookies:" ascii //weight: 1
        $x_1_4 = "xWin32_DiskDrive" wide //weight: 1
        $x_1_5 = "Brute.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

