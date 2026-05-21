import unittest
from unittest.mock import patch

from hyping.discovery.mdns import (
    MDNSService,
    _parse_browse_instances,
    _parse_reached_host,
    _parse_txt_record,
    as_mdns_hostname,
    find_mdns_services_by_hostname,
    format_mdns_key_values,
    format_mdns_service,
    merge_mdns_services,
    normalize_mdns_hostname,
    resolve_mdns_service,
)


class MDNSTests(unittest.TestCase):
    def test_hostname_final_dot_is_optional(self) -> None:
        self.assertEqual(
            normalize_mdns_hostname("haozdeMacBook-Air.local."),
            "haozdeMacBook-Air.local",
        )
        self.assertEqual(
            as_mdns_hostname("haozdeMacBook-Air.local."),
            "haozdeMacBook-Air.local",
        )

    def test_parse_dns_sd_resolve_output(self) -> None:
        output = """
        date can be reached at haozdeMacBook-Air.local.:631 (interface 14)
        txtvers=1 qtotal=1 note=✖️昊z的MacBook\\032Air
        ty=Lenovo\\032M101DW\\032Pro rpBA=E4:91:62:AB:0D:57
        """

        self.assertEqual(
            _parse_reached_host(output),
            ("haozdeMacBook-Air.local", 631),
        )
        self.assertEqual(
            _parse_txt_record(output),
            {
                "txtvers": "1",
                "qtotal": "1",
                "note": "✖️昊z的MacBook Air",
                "ty": "Lenovo M101DW Pro",
                "rpBA": "E4:91:62:AB:0D:57",
            },
        )

    def test_parse_browse_instances(self) -> None:
        output = """
        Timestamp     A/R    Flags  if Domain  Service Type  Instance Name
        10:00:00.000  Add        3  14 local.  _ipp._tcp.    Lenovo M101DW Pro
        """

        self.assertEqual(
            _parse_browse_instances(output, "_ipp._tcp", "local"),
            ["Lenovo M101DW Pro"],
        )

    def test_resolve_mdns_service_and_format(self) -> None:
        output = """
        date can be reached at haozdeMacBook-Air.local.:631 (interface 14)
        txtvers=1 qtotal=1 note=✖️昊z的MacBook\\032Air ty=Lenovo\\032M101DW\\032Pro
        """

        with patch("hyping.discovery.mdns._run_dns_sd", return_value=output):
            service = resolve_mdns_service("Lenovo M101DW Pro", "_ipp._tcp")

        formatted = format_mdns_service(service)
        self.assertIn("hostname\thaozdeMacBook-Air.local", formatted)
        self.assertIn("note\t✖️昊z的MacBook Air", formatted)
        self.assertIn("ty\tLenovo M101DW Pro", formatted)

    def test_find_mdns_services_by_hostname_strips_final_dot(self) -> None:
        browse_output = """
        10:00:00.000  Add        3  14 local.  _ipp._tcp.    Lenovo M101DW Pro
        """
        resolve_output = """
        date can be reached at haozdeMacBook-Air.local.:631 (interface 14)
        txtvers=1
        """

        with patch(
            "hyping.discovery.mdns._run_dns_sd",
            side_effect=[browse_output, resolve_output],
        ):
            services = find_mdns_services_by_hostname(
                "haozdeMacBook-Air.local.",
                service_types=("_ipp._tcp",),
            )

        self.assertEqual(len(services), 1)
        self.assertEqual(services[0].hostname, "haozdeMacBook-Air.local")

    def test_merge_mdns_services_combines_records(self) -> None:
        services = [
            MDNSService(
                instance="Printer",
                service_type="_ipp._tcp",
                domain="local",
                hostname="haozdeMacBook-Air.local",
                port=631,
                txt={"note": "✖️昊z的MacBook Air", "ty": "Lenovo"},
            ),
            MDNSService(
                instance="AirPlay",
                service_type="_airplay._tcp",
                domain="local",
                hostname="haozdeMacBook-Air.local",
                port=7000,
                txt={"model": "Mac14,2", "features": "0x1"},
            ),
        ]

        formatted = format_mdns_key_values(merge_mdns_services(services))

        self.assertIn("hostname\thaozdeMacBook-Air.local", formatted)
        self.assertIn("service\tPrinter, AirPlay", formatted)
        self.assertIn("note\t✖️昊z的MacBook Air", formatted)
        self.assertIn("model\tMac14,2", formatted)


if __name__ == "__main__":
    unittest.main()
