rule Backdoor_Linux_BPFDoor_A_2147819320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/BPFDoor.A!MTB"
        threat_id = "2147819320"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "BPFDoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 98 48 8d 50 0e 48 8d 85 ?? fd ff ff 48 01 d0 48 89 45 ?? 48 8b 45 ?? 0f b6 40 0c c0 e8 04 0f b6 c0 c1 e0 02 89 45 ?? 8b 45 ?? 48 63 d0 8b 45 ?? 48 98 [0-5] 48 8d 50 ?? 48 8d 85 ?? fd ff ff}  //weight: 2, accuracy: Low
        $x_2_2 = {48 83 c0 14 48 89 45 ?? 48 8b 45 ?? 48 83 c0 08 48 89 45 ?? eb ?? 48 8b 45 ?? 48 83 c0 14 48 89 45 ?? 48 8b 45 ?? 48 83 c0 08 48 89 45}  //weight: 2, accuracy: Low
        $x_2_3 = {55 48 89 e5 48 83 ec 30 48 89 7d d8 48 c7 45 e0 3c 08 0a 49 48 c7 45 e8 00 00 00 00 48 c7 45 f0 3c 08 0a 49 48 c7 45 f8 00 00 00 00 48 8d ?? e0 48 8b ?? d8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_BPFDoor_B_2147819609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/BPFDoor.B!MTB"
        threat_id = "2147819609"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "BPFDoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 85 c4 fd ff ff 8d 50 0e 8b 45 ?? 8d 04 02 89 45 ?? 8b 45 ?? 0f b6 40 0c 0f b6 c0 25 f0 00 00 00 c1 f8 04 c1 e0 02 89 45 ?? 8d 85 c4 fd ff ff 8d 50 0e 8b 45 ?? 01 c2 8b 45 ?? 8d 04 02 89 45}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c0 14 89 45 ?? 8b 45 ?? 83 c0 08 89 45 ?? eb 12 8b 45 ?? 83 c0 14 89 45 ?? 8b 45 ?? 83 c0 08 89 45}  //weight: 1, accuracy: Low
        $x_1_3 = {55 89 e5 83 ec 18 c7 45 f0 3c 08 0a 49 c7 45 f4 00 00 00 00 c7 45 f8 3c 08 0a 49 c7 45 fc 00 00 00 00 8d 45 f0 89 44 24 04 8b 45 08 89 04 24 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_BPFDoor_C_2147819610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/BPFDoor.C!MTB"
        threat_id = "2147819610"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "BPFDoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "icmpcmd" ascii //weight: 1
        $x_1_2 = "udpcmd" ascii //weight: 1
        $x_1_3 = "getpassw" ascii //weight: 1
        $x_2_4 = {ff fe ff 48 89 45 ?? 48 8b 45 ?? c6 00 08 48 8b 45 ?? c6 40 01 00 48 8b 45 ?? 66 c7 40 02 00 00 48 8b 45 ?? 66 c7 40 06 d2 04 e8 [0-5] 89 c2 48 8b 45 ?? 66 89 50 04 8b 45 [0-5] 48 8d ?? ?? ff fe ff 48 ?? ?? 08 48 89 ?? be ?? 46 60}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_BPFDoor_D_2147819611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/BPFDoor.D!MTB"
        threat_id = "2147819611"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "BPFDoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/var/run/haldrund.pid" ascii //weight: 1
        $x_2_2 = {9d e3 bf 80 f0 27 a0 44 03 12 42 82 82 10 60 3c c2 27 bf e0 c0 27 bf e4 03 12 42 82 82 10 60 3c c2 27 bf ?? c0 27 bf ?? 82 07 bf e0 d0 07 a0 44 92 10 00 01}  //weight: 2, accuracy: Low
        $x_2_3 = {9d e3 bf 78 f0 27 a0 44 03 00 00 4e 82 10 60 67 9a ?? ?? ?? 98 10 20 16 90 10 00 0d 92 10 00 01 94 10 00 0c 40 [0-5] 01 00 00 00 40 [0-5] 01 00 00 00 9a 10 00 08 03 00 00 91 82 10 61 c4 c2 00 40 00 80 a3 40 01 [0-5] 01 00 00 00 82 ?? ?? ?? 90 10 00 01}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_BPFDoor_E_2147819614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/BPFDoor.E!MTB"
        threat_id = "2147819614"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "BPFDoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "kdmtmpflush" ascii //weight: 1
        $x_1_2 = "pickup -l -t fifo -u" ascii //weight: 1
        $x_1_3 = "dbus-daemon --system" ascii //weight: 1
        $x_2_4 = {ff ff 48 83 c0 14 48 89 85 ?? ?? ff ff 48 8b 85 ?? ?? ff ff 48 83 c0 08 48 89 85 ?? ?? ff ff eb ?? 48 8b 85 ?? ?? ff ff 48 83 c0 14 48 89 85 ?? ?? ff ff 48 8b 85 ?? ?? ff ff 48 83 c0 08 48 89 85 ?? ?? ff ff}  //weight: 2, accuracy: Low
        $x_2_5 = {55 89 e5 83 ec 18 c7 45 e8 3c 08 0a 49 c7 45 ec 00 00 00 00 c7 45 f0 3c 08 0a 49 c7 45 f4 00 00 00 00 83 ec 08 8d 45 e8 50 ff 75 08 e8 [0-5] 83 c4 10 c9 c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_BPFDoor_F_2147850526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/BPFDoor.F!MTB"
        threat_id = "2147850526"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "BPFDoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 31 c9 45 31 c0 31 c9 ba 00 00 01 00 48 89 de 89 ef e8 99 fd ff ff 85 c0}  //weight: 1, accuracy: High
        $x_1_2 = "/var/run/initd.lock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_BPFDoor_G_2147943669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/BPFDoor.G!MTB"
        threat_id = "2147943669"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "BPFDoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 45 ff 83 c0 01 88 45 ff 0f b6 55 ff 48 8b 45 f0 48 01 d0 0f b6 00 00 45 fe 0f b6 55 fe 48 8b 45 f0 48 01 c2 0f b6 4d ff 48 8b 45 f0 48 01 c8 48 89 d6 48 89 c7 e8 7c fe ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 45 f0 48 01 d0 0f b6 10 0f b6 4d fe 48 8b 45 f0 48 01 c8 0f b6 00 01 d0 88 45 ef 8b 45 f8 48 63 d0 48 8b 45 d8 48 01 c2 8b 45 f8 48 63 c8 48 8b 45 d8 48 01 c8 0f b6 08 0f b6 75 ef 48 8b 45 f0 48 01 f0 0f b6 00 31 c8 88 02 83 45 f8 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_BPFDoor_I_2147947301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/BPFDoor.I!MTB"
        threat_id = "2147947301"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "BPFDoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/bin/rm -f /dev/shm/%s;/bin/cp %s /dev/shm/%s && /bin/chmod 755 /dev/shm/%s && /dev/shm/%s --init && /bin/rm -f /dev/shm/%s" ascii //weight: 1
        $x_1_2 = "/sbin/iptables -t nat -A PREROUTING -p tcp -s %s --dport %d -j REDIRECT --to-ports %d" ascii //weight: 1
        $x_2_3 = {45 0f b6 d8 49 01 c3 45 8a 33 44 88 36 41 88 13 02 16 0f b6 d2 8a 14 10 41 30 14 3a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

