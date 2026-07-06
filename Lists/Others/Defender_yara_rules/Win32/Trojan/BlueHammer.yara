rule Trojan_Win32_BlueHammer_RA_2147973015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlueHammer.RA!AMTB"
        threat_id = "2147973015"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlueHammer"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "[%02d:%02d:%02d.%03d] [*] === Stage 5: SAM Hash Dump ===" ascii //weight: 2
        $x_2_2 = "BlueHammer-FileIdentity-v1" ascii //weight: 2
        $x_2_3 = "BlueHammer-SyncRoot-v1" ascii //weight: 2
        $x_2_4 = "[%02d:%02d:%02d.%03d] [+] SYSTEM shell spawned in session %u" ascii //weight: 2
        $x_2_5 = "cmd.exe /c start /min conhost.exe -- cmd.exe" wide //weight: 2
        $x_2_6 = "BlueHammer.exe" wide //weight: 2
        $x_2_7 = "[%02d:%02d:%02d.%03d] [+] Batch oplock acquired" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

