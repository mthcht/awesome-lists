rule HackTool_Linux_Cymothoa_A_2147783546_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Cymothoa.A!MTB"
        threat_id = "2147783546"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Cymothoa"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "injecting code into 0x%.8x" ascii //weight: 1
        $x_1_2 = "cymothoa -p <pid> -s <shellcode_number" ascii //weight: 1
        $x_1_3 = "Runtime shellcode injection, for stealthy backdoors" ascii //weight: 1
        $x_1_4 = "xenomuta.tuxfamily.org" ascii //weight: 1
        $x_1_5 = "audio (knock knock knock) via /dev/dsp" ascii //weight: 1
        $x_1_6 = "alarm() backdoor (requires -j -y) bind port, fork on accept" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

