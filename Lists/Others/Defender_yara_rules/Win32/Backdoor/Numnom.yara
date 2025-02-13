rule Backdoor_Win32_Numnom_A_2147606108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Numnom.A"
        threat_id = "2147606108"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Numnom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Port>%i</NewExternal" ascii //weight: 1
        $x_1_2 = "*update \"" ascii //weight: 1
        $x_1_3 = "downloaded to: <%s>" ascii //weight: 1
        $x_1_4 = "SRV: rip? %i" ascii //weight: 1
        $x_1_5 = "SRV: UPGRADE <%s>" ascii //weight: 1
        $x_1_6 = "SRV: IPLIST" ascii //weight: 1
        $x_1_7 = "new=<%s>, old=<%s>, self=<%s>" ascii //weight: 1
        $x_1_8 = "writing to HKCU/autorun key..." ascii //weight: 1
        $x_1_9 = "is not running, unrest." ascii //weight: 1
        $x_1_10 = "SOCKS port: %i" ascii //weight: 1
        $x_5_11 = {59 b9 40 9c 00 00 99 f7 f9 8d 82 ?? ?? 00 00 a3 ?? ?? 40 00 a1 ?? ?? 40 00 3d 5a 4d 00 00 74 ?? 3d 18 06 00 00 74}  //weight: 5, accuracy: Low
        $x_5_12 = {c7 85 64 ff ff ff fa 00 00 00 e8 ?? ?? ff ff 89 85 7c ff ff ff 85 c0 0f 84 ?? ?? 00 00 66 c7 85 6c ff ff ff 02 00 8b 85 7c ff ff ff 89 85 70 ff ff ff 68 e7 14 00 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

