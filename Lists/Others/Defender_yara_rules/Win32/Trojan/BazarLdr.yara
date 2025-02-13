rule Trojan_Win32_BazarLdr_C_2147766864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BazarLdr.C!ibt"
        threat_id = "2147766864"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BazarLdr"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "powershell.exe -Command \"& {Add-MpPreference -ExclusionPath" wide //weight: 2
        $x_2_2 = "Set-ExecutionPolicy -Scope Process Bypass" wide //weight: 2
        $x_1_3 = "CurrentVersion\\RunOnce" wide //weight: 1
        $x_1_4 = "selfDelete" ascii //weight: 1
        $x_1_5 = "autorun" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_BazarLdr_A_2147766895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BazarLdr.A!MTB"
        threat_id = "2147766895"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BazarLdr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "WindowsSDK7-Samples-master\\com\\administration\\spy\\Win32\\Release\\ComSpy.pdb" ascii //weight: 10
        $x_1_2 = "Software\\Microsoft\\COMSpy" wide //weight: 1
        $x_1_3 = "COM.SpyContainer = s 'SpyCon Class'" ascii //weight: 1
        $x_1_4 = "&Clear All Events" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BazarLdr_XA_2147768913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BazarLdr.XA!MTB"
        threat_id = "2147768913"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BazarLdr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Process Doppelganging test" wide //weight: 1
        $x_1_2 = "Cannot read remote PEB" ascii //weight: 1
        $x_1_3 = "SHA384" wide //weight: 1
        $x_1_4 = "bcrypt.dll" ascii //weight: 1
        $x_1_5 = "CryptStringToBinaryA" ascii //weight: 1
        $x_1_6 = "CryptAcquireContextA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

