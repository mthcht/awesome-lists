rule Trojan_Win32_Balrok_DW_2147891468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Balrok.DW!MTB"
        threat_id = "2147891468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Balrok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Tom Clancys Ghost Recon - Desert Siege no cd crack.exe" ascii //weight: 1
        $x_1_2 = "Sponge Bob Square Pants - Operation Krabby Patty no cd crack.exe" ascii //weight: 1
        $x_1_3 = "balROK_state[Crack].EXE" ascii //weight: 1
        $x_1_4 = "Star Wars - Jedi Knight - Jedi Academy no cd crack.exe" ascii //weight: 1
        $x_1_5 = "Command & Conquer - Generals no cd crack.exe" ascii //weight: 1
        $x_1_6 = "RollerCoaster Tycoon NO CD Crack (Including Attractions Pack).exe" ascii //weight: 1
        $x_1_7 = "Call Of Duty no cd crack.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

