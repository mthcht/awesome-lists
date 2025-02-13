rule Trojan_Win32_MhztLocker_A_2147842673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MhztLocker.A!MTB"
        threat_id = "2147842673"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MhztLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 2
        $x_2_2 = "Windows Defender" ascii //weight: 2
        $x_2_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii //weight: 2
        $x_2_4 = "DisableTaskmgr" ascii //weight: 2
        $x_2_5 = "DisableRegistryTools" ascii //weight: 2
        $x_2_6 = "start echo This PC Is Locked! If You Want Unlock Contact Owner!" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

