rule Trojan_Win32_Dllinjector_O_2147965197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dllinjector.O!AMTB"
        threat_id = "2147965197"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dllinjector"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "gamesense.live" ascii //weight: 2
        $x_2_2 = "Please, launch CS:GO yourself." ascii //weight: 2
        $x_2_3 = "VAC bypass injection" ascii //weight: 2
        $x_2_4 = "[PROCESS INJECTION]" ascii //weight: 2
        $x_2_5 = "YOU CAN GET VAC BAN" ascii //weight: 2
        $x_2_6 = "DLL path written successfully." ascii //weight: 2
        $x_2_7 = "skeet.dll" ascii //weight: 2
        $x_2_8 = "waiting for csgo.exe" ascii //weight: 2
        $x_2_9 = "\\injector\\skeet-injector.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

