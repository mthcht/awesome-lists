rule Trojan_Win32_Trickbotpw_A_2147766701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbotpw.A!mod"
        threat_id = "2147766701"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbotpw"
        severity = "Critical"
        info = "mod: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Grab_Passwords_Chrome(0)" ascii //weight: 1
        $x_1_2 = "Grab_Passwords_Chrome() success" ascii //weight: 1
        $x_1_3 = "Grab_Passwords_Chrome(): Can't open database" ascii //weight: 1
        $x_1_4 = "\\Google\\Chrome\\User Data\\Default\\Login Data.bak" ascii //weight: 1
        $x_1_5 = "[Reflection.Assembly]::LoadFile(\"$binpath\\KeePass.exe\")" ascii //weight: 1
        $x_1_6 = "Write-warning \"Unable Load KeePass Binarys\"" ascii //weight: 1
        $x_1_7 = "mimikatz" ascii //weight: 1
        $x_1_8 = "Internet Explorer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

