rule Trojan_Win32_Taloc_B_2147691670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Taloc.B"
        threat_id = "2147691670"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Taloc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {77 69 6e 64 69 72 00 55 30 39 47 56 46 64 42 55 6b 56 63 54 57 6c 6a 63 6d 39 7a 62 32 5a 30 58 46 64 70 62 6d 52 76 64 33 4e 63 51 33 56 79 63 6d 56 75 64 46 5a 6c 63 6e 4e 70 62 32 35 63 55 6e 56 75 58 41 3d 3d 00}  //weight: 1, accuracy: High
        $x_1_2 = {6e 69 63 6b 6e 61 6d 65 22 3a 22 00}  //weight: 1, accuracy: High
        $x_1_3 = {61 48 52 30 63 44 6f 76 4c 77 3d 3d 00 4c 32 6c 77 4c 6e 42 6f 63 41 3d 3d 00 4c 33 56 77 62 47 39 68 5a 43 35 77 61 48 41 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = "Accept-Language: zh-cn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Taloc_D_2147693938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Taloc.D"
        threat_id = "2147693938"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Taloc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Nril\\syetom.exe" ascii //weight: 1
        $x_1_2 = "/cgi_personal_card?uin=" ascii //weight: 1
        $x_1_3 = "nickname\":\"" ascii //weight: 1
        $x_1_4 = "syetom" wide //weight: 1
        $x_1_5 = "\\Program Files\\Nril" wide //weight: 1
        $x_1_6 = {52 75 6e 5c [0-4] 77 69 6e 64 69 72 [0-4] 5c 53 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Taloc_F_2147697431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Taloc.F"
        threat_id = "2147697431"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Taloc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Accept-Language: zh-cn" ascii //weight: 1
        $x_1_2 = {61 48 52 30 63 44 6f 76 4c 77 3d 3d 00 4c 32 6c 77 4c 6e 42 6f 63 41 3d 3d 00 4c 33 56 77 62 47 39 68 5a 43 35 77 61 48 41 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = "RG9tYWlOYW1lU3l0ZW0=" ascii //weight: 1
        $x_1_4 = "XC4uLi5cVGVtcG9yYXJ5RmlsZQ==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Taloc_G_2147697614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Taloc.G"
        threat_id = "2147697614"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Taloc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aHR0cDovL3VzZXJzLnF6b25lLnFxLmNvbS9mY2ctYmluL2NnaV9nZXRfcG9ydHJhaXQuZmNnP3VpbnM9" ascii //weight: 1
        $x_1_2 = "aHR0cDovLzQ5LjE0My4yMDUuMjEvQ291bnQuYXNwP3Zlcj0wMDEmbWFjPQ==" ascii //weight: 1
        $x_1_3 = "U29mdHdhcmVcTWljcm9zb2Z0XEludGVybmV0IEV4cGxvcmVyXE1haW5cU3RhcnQgUGFnZQ==" ascii //weight: 1
        $x_1_4 = "d3d3Lm5hdmVyLmNvbQ==" ascii //weight: 1
        $x_1_5 = "cmVnc3ZyMzIgL3MgemlwZmxkci5kbGw=" ascii //weight: 1
        $x_1_6 = "XEFwcERhdGFcTG9jYWxMb3dc" ascii //weight: 1
        $x_1_7 = "L3VwbG9hZC5waHA=" ascii //weight: 1
        $x_1_8 = {73 79 73 74 6f 6d 00 61 77 65 6b 68 73 67 00 35 39 36 32 35 37 44 44 39 33 46 33 30 39 35 36 41 30 35 37 41 32 39 46 33 41 39 39}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

