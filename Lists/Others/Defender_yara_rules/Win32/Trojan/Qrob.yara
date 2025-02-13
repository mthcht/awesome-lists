rule Trojan_Win32_Qrob_RPP_2147841145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qrob.RPP!MTB"
        threat_id = "2147841145"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qrob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Discord Canary" ascii //weight: 1
        $x_1_2 = "Opera GX" ascii //weight: 1
        $x_1_3 = "Sputnik" ascii //weight: 1
        $x_1_4 = "YandexBrowser" ascii //weight: 1
        $x_1_5 = "encrypted_key" ascii //weight: 1
        $x_1_6 = "dQw4w9WgXcQ" ascii //weight: 1
        $x_1_7 = "b64decode" ascii //weight: 1
        $x_1_8 = "getip()" ascii //weight: 1
        $x_1_9 = "Token Grabber" ascii //weight: 1
        $x_1_10 = "Astraa" ascii //weight: 1
        $x_1_11 = "atio.jpg" ascii //weight: 1
        $x_1_12 = "webhooks" ascii //weight: 1
        $x_1_13 = "payload.encode()" ascii //weight: 1
        $x_1_14 = "get_token()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

