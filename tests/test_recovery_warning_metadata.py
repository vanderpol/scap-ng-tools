"""Four historical blockers are warning metadata, not native Input constraints."""
from copy import deepcopy
from hashlib import sha256
import os
from pathlib import Path
import tempfile
import unittest
import zipfile
import xml.etree.ElementTree as ET

from scap_ng_tools.converter.recovery04 import recover_benchmark,_classes
from scap_ng_tools.converter.direct04 import load_runtime
from scap_ng_tools.contracts import FrozenSchemaSnapshot

PINS=[('U_RHEL_7_V3R15_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip',
       '17c3ddd4d4ae40bd7ca3443dae0a0c9ed921444a57c34bff357f9f885e0d9ab8',
       ['xccdf_mil.disa.stig_rule_SV-204418r982188_rule','xccdf_mil.disa.stig_rule_SV-204420r982200_rule']),
      ('U_Oracle_Linux_7_V3R3_STIG_SCAP_1-4_Benchmark-enhancedV16-signed.zip',
       '0235429534dfc1149824f1a6b5144f73e16dc28d84d899c638cc5ede31da8c1a',
       ['xccdf_mil.disa.stig_rule_SV-221681r1015177_rule','xccdf_mil.disa.stig_rule_SV-221683r1038967_rule'])]


class WarningMetadataRecovery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema=os.environ.get('SCAP_NG_SCHEMA_ROOT');root=os.environ.get('SCAP_NG_ADDITIONAL_FIXTURES_ROOT')
        if not cls.schema or not root:raise unittest.SkipTest('Pinned public schema and original signed fixtures required')
        cls.root=Path(root)

    def test_four_source_rules_recover_without_treating_warnings_as_constraints(self):
        for filename,pin,ids in PINS:
            with self.subTest(source=filename):
                source=self.root/filename
                self.assertEqual(sha256(source.read_bytes()).hexdigest(),pin)
                docs,trace,ledger=recover_benchmark(schema_root=self.schema,source=source,sha256_pin=pin,rule_ids=ids)
                self.assertEqual(ledger['summary']['statuses'],{'AUTOMATED_DRAFT':2})
                self.assertEqual(ledger['summary']['manual_choices'],2)
                benchmark=next(d['benchmark'] for d in docs.values() if 'benchmark' in d)
                self.assertEqual(len(benchmark['parameters']),2)
                for parameter in benchmark['parameters']:
                    self.assertEqual(parameter['warnings'],[{'text':'This will only apply to newly created accounts',
                        'category':'general','language':'en-US'}])
                    self.assertNotIn('constraints',parameter)
                self.assertTrue(all(not r['blockers'] for r in ledger['rules']))

    def test_real_value_bound_and_complex_warning_remain_blocked(self):
        engine=load_runtime()
        from v04_direct_scap_source import SourceModel,XCCDF
        filename,pin,ids=PINS[0];original=SourceModel(self.root/filename,pin)
        for kind in ('real-bound','complex-warning'):
            model=deepcopy(original)
            rule=model.rules[ids[0]];check=next(c for c in rule.findall('{'+XCCDF+'}check') if c.find('{'+XCCDF+'}check-export') is not None)
            export=check.find('{'+XCCDF+'}check-export');value=model.nodes[model.benchmark_component][export.get('value-id')]
            if kind=='real-bound':ET.SubElement(value,'{'+XCCDF+'}lower-bound').text='0'
            else:ET.SubElement(value.find('{'+XCCDF+'}warning'),'unsupported').text='Complex source warning'
            with tempfile.TemporaryDirectory() as folder:
                p=Path(folder)/'controlled.zip'
                with zipfile.ZipFile(p,'w') as z:z.writestr(model.member,ET.tostring(model.root))
                _,_,ledger=recover_benchmark(schema_root=self.schema,source=p,sha256_pin=sha256(p.read_bytes()).hexdigest(),rule_ids=[ids[0]])
            self.assertEqual(ledger['summary']['statuses'],{'BLOCKED':1})
            self.assertTrue(any('constraint' in b.lower() or 'warning' in b.lower() for b in ledger['rules'][0]['blockers']))

    def test_variable_reference_only_accepts_explicit_defaults(self):
        engine=load_runtime();Source,Visitor=_classes(engine)
        filename,pin,_=PINS[0];source=Source(self.root/filename,pin,draft_compatibility=True)
        snapshot=FrozenSchemaSnapshot(self.schema)
        mappings=snapshot.supported_mappings(engine.CAPABILITIES)
        component=next(k for k,n in source.components.items() if n.tag.endswith('}oval_definitions'))
        visitor=Visitor(source,component,mappings)
        visitor.named_variable=lambda ident:'known-source-variable'
        ns='http://oval.mitre.org/XMLSchema/oval-definitions-5#independent'
        node=ET.Element('{'+ns+'}variable_object',id='controlled-object')
        ref=ET.SubElement(node,'{'+ns+'}var_ref',datatype='string',operation='equals');ref.text='original-variable-id'
        expected={'capability':'variable.value','variable':'known-source-variable'}
        self.assertEqual(visitor.convert_object(node),expected)
        ref.set('operation','pattern match')
        with self.assertRaisesRegex(ValueError,'nondefault variable reference'):visitor.convert_object(node)
        ref.set('operation','equals');ref.set('datatype','int')
        with self.assertRaisesRegex(ValueError,'nondefault variable reference'):visitor.convert_object(node)

if __name__=='__main__':unittest.main()
