rule Trojan_Win32_Rapowsom_A_2147741245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rapowsom.A!cmd"
        threat_id = "2147741245"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rapowsom"
        severity = "Critical"
        info = "cmd: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c" wide //weight: 1
        $x_1_2 = "vssadmin.exe delete shadows /all /quiet" wide //weight: 1
        $x_1_3 = "bcdedit /set {default} recoveryenabled no" wide //weight: 1
        $x_1_4 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

