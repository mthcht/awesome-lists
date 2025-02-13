rule Trojan_Win32_MuddyRope_B_2147741357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MuddyRope.B"
        threat_id = "2147741357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MuddyRope"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "CiscoAny.exe" ascii //weight: 20
        $x_20_2 = "%EIdSocksUDPNotSupportedBySOCKSVersion" ascii //weight: 20
        $x_20_3 = "{$output = New-Object \"System.Text.StringBuilder\"" ascii //weight: 20
        $x_40_4 = "http://zstoreshoping.ddns.net/Data" ascii //weight: 40
        $x_40_5 = "http://amazo0n.serveftp.com/Data/" ascii //weight: 40
        $x_40_6 = "http://googleads.hopto.org" ascii //weight: 40
        $x_20_7 = "\\WhqMSsK%" ascii //weight: 20
        $x_10_8 = "\\IOCMV.ps1" ascii //weight: 10
        $x_10_9 = "\\Lib.ps1" ascii //weight: 10
        $x_1_10 = "Builds\\TpAddons\\IndyNet\\System\\IdStreamVCL.pas" ascii //weight: 1
        $x_1_11 = "Builds\\TpAddons\\IndyNet\\System\\IdGlobal.pas" ascii //weight: 1
        $x_1_12 = "builds\\TpAddons\\IndyNet\\System\\IdStack.pas" ascii //weight: 1
        $x_1_13 = "builds\\TpAddons\\IndyNet\\Core\\IdIOHandler.pas" ascii //weight: 1
        $x_1_14 = "builds\\TpAddons\\IndyNet\\Protocols\\IdCoder3to4.pas" ascii //weight: 1
        $x_1_15 = "builds\\TpAddons\\IndyNet\\Protocols\\IdZLibCompressorBase.pas" ascii //weight: 1
        $x_1_16 = "builds\\TpAddons\\IndyNet\\Protocols\\IdHTTP.pas" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_20_*) and 2 of ($x_10_*))) or
            ((3 of ($x_20_*))) or
            ((1 of ($x_40_*) and 2 of ($x_10_*))) or
            ((1 of ($x_40_*) and 1 of ($x_20_*))) or
            ((2 of ($x_40_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_MuddyRope_C_2147755313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MuddyRope.C"
        threat_id = "2147755313"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MuddyRope"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 50 50 44 41 54 41 [0-16] 5c 4c 69 62 2e 70 73 31 [0-25] 68 74 74 70 3a 2f 2f [0-42] 2e 64 61 74 [0-48] 2d 65 78 65 63 [0-5] 62 79 70 61 73 73 [0-8] 50 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 [0-6] 4f 70 65 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

