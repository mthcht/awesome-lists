rule Backdoor_MacOS_Twenbc_A_2147832428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Twenbc.A!MTB"
        threat_id = "2147832428"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Twenbc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 f7 48 89 f5 e8 ?? ?? ?? 00 4c 8d 64 05 00 48 83 f8 0f 48 89 44 24 08 76 1b 48 8d 74 24 08 31 d2 48 89 df e8 ?? ?? ?? 00 48 89 03 48 8b 44 24 08 48 89 43 10}  //weight: 1, accuracy: Low
        $x_1_2 = "/var/run/legacy_agent.pid" ascii //weight: 1
        $x_1_3 = "sw_vers | grep \"ProductVersion\" | tr -dc '0-9.'" ascii //weight: 1
        $x_1_4 = "3Eqzwr3YjJ3C6ucQGUNrqRNth9YENQfU" ascii //weight: 1
        $x_1_5 = "UpP'CQB\"wHHO&a6Obu<t$a@n" ascii //weight: 1
        $x_1_6 = "machdep.cpu.brand_string" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

