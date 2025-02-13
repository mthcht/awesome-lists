rule VirTool_Win32_Dogho_A_2147748145_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Dogho.A"
        threat_id = "2147748145"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogho"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/goDoH/main.go" ascii //weight: 1
        $x_1_2 = "/goDoH/cmd/c2.go" ascii //weight: 1
        $x_1_3 = "/sensepost/godoh/cmd.executeCommand" ascii //weight: 1
        $x_1_4 = "/godoh/dnsserver.(*Handler).ServeDNS" ascii //weight: 1
        $x_1_5 = "/godoh/dnsclient.(*RawDNS).Lookup" ascii //weight: 1
        $x_1_6 = {2f 67 6f 64 6f 68 2f [0-8] 2e 44 65 63 72 79 70 74}  //weight: 1, accuracy: Low
        $x_1_7 = "/godoh/protocol.(*Command).GetOutgoing" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

