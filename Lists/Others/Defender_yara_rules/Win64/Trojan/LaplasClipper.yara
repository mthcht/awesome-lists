rule Trojan_Win64_LaplasClipper_B_2147844498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LaplasClipper.B!MTB"
        threat_id = "2147844498"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LaplasClipper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "LpwwsiPMYjGhnhgCmjqv/mzwj74aht7eMsbeGu-za/68E44VMatiFM7COEA2Tn/2CFY04vPANsaze86lsjv" ascii //weight: 2
        $x_2_2 = "net/url" ascii //weight: 2
        $x_2_3 = "os/exec" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LaplasClipper_EN_2147849716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LaplasClipper.EN!MTB"
        threat_id = "2147849716"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LaplasClipper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "6sKoVuuBsl_KP-yheX5P/ZNk90HJ6fR0jhMvT5U1e/1-Zd-iJCkcIETQR5OePX/VV3xK13jWT5pRk_BToag" ascii //weight: 1
        $x_1_2 = "laplasbuild/clipboard" ascii //weight: 1
        $x_1_3 = "GetClipboardData" ascii //weight: 1
        $x_1_4 = "GetComputerNameW" ascii //weight: 1
        $x_1_5 = "Set-CookieUser-AgentW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

