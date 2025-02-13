rule Trojan_Win32_Smasarch_A_2147680249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smasarch.A"
        threat_id = "2147680249"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smasarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 6d 73 73 74 61 74 75 73 2e 63 6f 6d 2f 73 6d 73 2f 69 73 76 61 6c 69 64 ?? 2e 70 68 70 3f 63 6f 64 65 3d ?? ?? ?? 26 63 6f 75 6e 74 72 79 3d ?? ?? 26 70 72 3d [0-32] 26 61 66 3d}  //weight: 1, accuracy: Low
        $x_1_2 = "shareware.pro" ascii //weight: 1
        $x_1_3 = "/BANNER" ascii //weight: 1
        $x_1_4 = "URL Parts Error" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smasarch_C_2147681280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smasarch.C"
        threat_id = "2147681280"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smasarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = ".php?pais=${COUNTRY}&tipo=sms&code=" ascii //weight: 3
        $x_1_2 = "smsLabelCode" ascii //weight: 1
        $x_1_3 = ",00 / SMS" ascii //weight: 1
        $x_1_4 = "Phone Number=6566" ascii //weight: 1
        $x_1_5 = "Include Adware=" ascii //weight: 1
        $x_1_6 = "Ask Advertising=" ascii //weight: 1
        $x_1_7 = "[SMSCheck]" ascii //weight: 1
        $x_2_8 = "send a Premium <SMS> with keyword <{smsalias}>" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Smasarch_B_2147681281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smasarch.B"
        threat_id = "2147681281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smasarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 68 61 72 65 77 61 72 65 2e 70 72 6f 2f 69 6e 64 65 78 66 72 2e 68 74 6d 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = "sms/isvalid2.php?code=" ascii //weight: 1
        $x_1_3 = "envoyer un SMS avec le mot SHARE" ascii //weight: 1
        $x_1_4 = "TXT_MESSAGESONE" ascii //weight: 1
        $x_1_5 = {43 68 61 71 75 65 20 53 4d 53 20 63 6f fb 74 65 20 31 2c 35 30 20 45 75 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smasarch_E_2147681282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smasarch.E"
        threat_id = "2147681282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smasarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "${TXT_MESSAGESONE}" ascii //weight: 1
        $x_1_2 = "${TXT_MESSAGES_AUSTRALIA}" ascii //weight: 1
        $x_1_3 = "sett min hjemmeside til Woofi verkt" ascii //weight: 1
        $x_1_4 = "40 Kroner/sms." ascii //weight: 1
        $x_1_5 = "pantallacodigo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smasarch_F_2147681283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smasarch.F"
        threat_id = "2147681283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smasarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "verify.smsstatus.com/sms/isvalid2.php?code=\\$R0&country=${COUNTRY}&pr=${PR}&af=${AF}&num=${NUM}" ascii //weight: 1
        $x_1_2 = "Custom Home=http://uk.woofi.info" ascii //weight: 1
        $x_1_3 = "panelsms1.English" ascii //weight: 1
        $x_1_4 = "Platform Kind=sms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smasarch_D_2147681284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smasarch.D"
        threat_id = "2147681284"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smasarch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "verify.smsstatus.com" ascii //weight: 1
        $x_1_2 = "shareware.pro/support" ascii //weight: 1
        $x_1_3 = "captura.bmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smasarch_AO_2147720733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smasarch.AO!bit"
        threat_id = "2147720733"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smasarch"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = {64 75 63 6b 64 6e 73 2e 6f 72 67 00 53 62 69 65 44 6c 6c}  //weight: 1, accuracy: High
        $x_1_3 = "captura.bmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

