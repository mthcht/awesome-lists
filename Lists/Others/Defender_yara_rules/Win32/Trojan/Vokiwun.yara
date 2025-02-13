rule Trojan_Win32_Vokiwun_A_2147709690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vokiwun.A!bit"
        threat_id = "2147709690"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vokiwun"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess" wide //weight: 10
        $x_10_2 = "  <URI>WPD\\Winsystem</URI>" wide //weight: 10
        $x_1_3 = "exe.rerolpxe\\" wide //weight: 1
        $x_1_4 = "function alert(){return;}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

