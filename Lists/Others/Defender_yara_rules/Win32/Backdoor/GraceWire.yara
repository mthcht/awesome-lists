rule Backdoor_Win32_GraceWire_D_2147731973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/GraceWire.D!dha"
        threat_id = "2147731973"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "GraceWire"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[config.c:ConfigFillServers" ascii //weight: 1
        $x_1_2 = "[rdp.c:RdpChannelAdd:" ascii //weight: 1
        $x_3_3 = "[target.c:WinMain:" ascii //weight: 3
        $x_1_4 = "SoftwareSASGeneration" wide //weight: 1
        $x_1_5 = "cmd /C net localgroup" wide //weight: 1
        $x_1_6 = "destroy_os" ascii //weight: 1
        $x_1_7 = "target_upload" ascii //weight: 1
        $x_1_8 = "target_rdp" ascii //weight: 1
        $x_1_9 = "target_module_load_external" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_GraceWire_E_2147735026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/GraceWire.E!dha"
        threat_id = "2147735026"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "GraceWire"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1000"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c3oeCSIfx0J6UtcV" ascii //weight: 1
        $x_1_2 = "er0ewjflk3qrhj81" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_GraceWire_F_2147743222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/GraceWire.F!dha"
        threat_id = "2147743222"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "GraceWire"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c3oeCSIfx0J6UtcV" ascii //weight: 1
        $x_1_2 = "er0ewjflk3qrhj81" ascii //weight: 1
        $x_1_3 = "netsh advfirewall firewall delete rule name=\"%s\"" wide //weight: 1
        $x_1_4 = "SoftwareSASGeneration" wide //weight: 1
        $x_1_5 = "gate port: %i (set with %s)" ascii //weight: 1
        $x_1_6 = "-------- [Current config]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

