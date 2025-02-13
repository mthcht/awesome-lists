rule Trojan_Linux_Xarcen_A_2147756255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Xarcen.A!MTB"
        threat_id = "2147756255"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Xarcen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BB2FA36AAA9541F0" ascii //weight: 1
        $x_1_2 = "DelService_form_pid" ascii //weight: 1
        $x_1_3 = "http_download" ascii //weight: 1
        $x_1_4 = "kill_pid" ascii //weight: 1
        $x_1_5 = "/etc/rc.d/rc%d.d/S90%s" ascii //weight: 1
        $x_1_6 = {8b 45 f4 0f b6 08 8b 55 f8 89 d0 c1 fa 1f f7 7d fc 89 d0 0f b6 80 88 f4 0c 08 89 ca 31 c2 8b 45 f4 88 10 83 45 f8 01 83 45 f4 01 8b 45 f8 3b 45 0c 7c cd 8b 45 08 c9 c3}  //weight: 1, accuracy: High
        $x_1_7 = "/etc/crontab && echo '*/3 * * * * root /etc/cron.hourly/gcc.sh' >> /etc/crontab" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Linux_Xarcen_B_2147772532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Xarcen.B!MTB"
        threat_id = "2147772532"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Xarcen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BB2FA36AAA9541F0" ascii //weight: 1
        $x_1_2 = "DelService_form_pid" ascii //weight: 1
        $x_1_3 = "bypass_iptables" ascii //weight: 1
        $x_1_4 = "HidePidPort" ascii //weight: 1
        $x_1_5 = "/etc/rc.d/rc%d.d/S90%s" ascii //weight: 1
        $x_1_6 = {10 30 1b e5 00 40 d3 e5 14 30 1b e5 03 00 a0 e1 18 10 1b e5 45 1a 00 eb 01 30 a0 e1 48 20 9f e5 03 30 d2 e7 03 30 24 e0 73 20 ef e6 10 30 1b e5 00 20 c3 e5 14 30 1b e5 01 30 83 e2 14 30 0b e5 10 30 1b e5 01 30 83 e2 10 30 0b e5 14 20 1b e5 24 30 1b e5 03 00 52 e1 e8 ff ff ba}  //weight: 1, accuracy: High
        $x_1_7 = "*/3 * * * * root /etc/cron.hourly/cron.sh' >> /etc/crontab" ascii //weight: 1
        $x_1_8 = "103.25.9.229" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Linux_Xarcen_C_2147773786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Xarcen.C!MTB"
        threat_id = "2147773786"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Xarcen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "#Groundhog" ascii //weight: 1
        $x_1_2 = "3 * * * * root /etc/cron.hourly/noc" ascii //weight: 1
        $x_1_3 = {74 63 70 00 2f 70 72 6f 63 2f 6e 65 74 2f 74 63 70 ?? 74 63 70 36 ?? 2f 70 72 6f 63 2f 6e 65 74 2f 74 63 70 36 ?? 25 64 09 7c 7c 25 73}  //weight: 1, accuracy: Low
        $x_1_4 = {65 78 65 63 20 25 73 0a ?? 2d 63 ?? 6b 70 75 4a 6b 73 63 3d ?? 25 73 ?? 6d 5a 4b 66 6d 5a 48 48 ?? 6b 5a 4f 57 6c 73 63 3d ?? 6e 70 2b 55 67 35 4f 4b 78 77 3d 3d ?? 6e 4a 4f 57 6e 35 53 62 6c 35 2f 48 ?? 69 4a 65 63 6b 35 61 66 78 77 3d 3d ?? 6e 4a 61 62 6e 63 63 3d ?? 6d 35 61 54 6a 4a 2f 48 00 25 64 3a 25 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Xarcen_B_2147823668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Xarcen.B!xp"
        threat_id = "2147823668"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Xarcen"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 24 08 7a 2c 0b 08 8b 45 f8 89 44 24 04 c7 04 24 83 2c 0b 08 e8 7c 04 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {83 7d f8 05 7e ae 8b 45 fc 89 44 24 08 c7 44 24 04 1e 2d 0b 08}  //weight: 1, accuracy: High
        $x_1_3 = {e8 21 02 00 00 c7 44 24 08 24 2d 0b 08 8b 45 fc 89 44 24 04 c7 04 24 83 2c 0b 08 e8 06 02 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

