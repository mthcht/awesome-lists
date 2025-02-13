rule Trojan_Win32_Corebot_A_2147707406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Corebot.A"
        threat_id = "2147707406"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Corebot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Local\\Heartbeat13" ascii //weight: 1
        $x_1_2 = "cmd.skip_unload" ascii //weight: 1
        $x_1_3 = "core.dga.key_fingerprint" ascii //weight: 1
        $x_1_4 = "core.dga.zones" ascii //weight: 1
        $x_1_5 = "core.dga.group" ascii //weight: 1
        $x_1_6 = "core.dga.domains_count" ascii //weight: 1
        $x_1_7 = "core.dga.url_path" ascii //weight: 1
        $x_1_8 = "core.server_key" ascii //weight: 1
        $x_1_9 = "powershell.exe -NonInteractive -NoProfile -NoLogo -ExecutionPolicy Unrestricted -File \"%s\" > \"%s\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_Corebot_C_2147726411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Corebot.C!bit"
        threat_id = "2147726411"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Corebot"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "fkit.pdb" ascii //weight: 2
        $x_2_2 = "df7689e6-c49f-4a86-82e8-6809a406872a" ascii //weight: 2
        $x_1_3 = "core.plugins_key" ascii //weight: 1
        $x_1_4 = "core.inject" ascii //weight: 1
        $x_1_5 = "core.servers" ascii //weight: 1
        $x_1_6 = "core.installed_file" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

