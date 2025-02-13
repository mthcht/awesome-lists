rule Trojan_Win32_TurlaMtx_A_2147845983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TurlaMtx.A"
        threat_id = "2147845983"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TurlaMtx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "carbon" ascii //weight: 4
        $x_1_2 = "Global\\MSCTF.Shared.MUTEX.ZRX" ascii //weight: 1
        $x_1_3 = "Global\\DBWindowsBase" ascii //weight: 1
        $x_1_4 = "Global\\IEFrame.LockDefaultBrowser" ascii //weight: 1
        $x_1_5 = "Global\\WinSta0_DesktopSessionMut" ascii //weight: 1
        $x_1_6 = "Global\\{5FA3BC02-920F-D42A-68BC-04F2A75BE158}" ascii //weight: 1
        $x_1_7 = "Global\\SENS.LockStarterCacheResource" ascii //weight: 1
        $x_1_8 = "Global\\ShimSharedMemoryLock" ascii //weight: 1
        $x_1_9 = "Global\\Stack.Trace.Multi.TOS" ascii //weight: 1
        $x_1_10 = "Global\\DatabaseTransSecurityLock" ascii //weight: 1
        $x_1_11 = "Global\\Exchange.Properties.B" ascii //weight: 1
        $x_1_12 = "Global\\TrackFirleSystemIntegrity" ascii //weight: 1
        $x_1_13 = "Global\\BitswapNormalOps" ascii //weight: 1
        $x_1_14 = "Global\\VB_crypto_library_backend" ascii //weight: 1
        $x_1_15 = "Global\\{E41B9AF4-B4E1-063B-7352-4AB6E8F355C7}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

