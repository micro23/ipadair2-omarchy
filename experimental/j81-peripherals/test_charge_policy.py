import unittest
from j81_usb_charge import target_code
class InputBudget(unittest.TestCase):
 def test_qualified_host_is_capped_at_500ma(self):self.assertEqual(target_code(True,500,320,4080000),34)
 def test_unconfigured_or_unadvertised_host_stays_at_original_budget(self):
  for configured,ma in [(False,500),(True,100),(True,0),(True,1000)]:self.assertEqual(target_code(configured,ma,320,4080000),2)
 def test_missing_hot_cold_or_high_voltage_telemetry_backs_off(self):
  for temp,voltage in [(None,4080000),(320,None),(99,4080000),(380,4080000),(320,4220000),(320,3400000)]:self.assertEqual(target_code(True,500,temp,voltage),2)
if __name__=='__main__':unittest.main()
