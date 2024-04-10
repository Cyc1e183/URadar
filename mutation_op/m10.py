from mutation_op import *
import utils

class mOP(MutationOP):
  __comment__ = "Mutation10: Change Extensions to Not commonly used"
  __mutate_type__ = "file"  # (file|request) ; type of target
  __exclusion_op__ = {'php':['M12_HTML','M12_XHTML','M04_ACE', 'M04_ARC', 'M04_ARJ', 'M04_BZ2', 'M04_DFXP', 'M04_EPUB', 'M04_GIF', 'M04_GPX', 'M04_GZIP', 'M04_JPG', 'M04_M4V', 'M04_MPA', 'M04_MPP', 'M04_NUMBERS', 'M04_ONETOC', 'M04_OXPS', 'M04_PAGES', 'M04_PDF', 'M04_PHAR', 'M04_PHP3', 'M04_PHP4', 'M04_PHP5', 'M04_PHP7', 'M04_PHTML', 'M04_PHT', 'M04_PNG', 'M04_TAR_GZ', 'M04_TXT', 'M04_WP', 'M04_WRI', 'M04_XHT', 'M04_XLA', 'M04_XLW', 'M04_XPS', 'M04_ZIP', 'M04_ZIPX', 'M07', 'M10', 'M11', 'M12_ACE', 'M12_ARC', 'M12_ARJ', 'M12_BZ2', 'M12_DFXP', 'M12_EPUB', 'M12_GIF', 'M12_GPX', 'M12_GZIP', 'M12_JPG', 'M12_M4V', 'M12_MPA', 'M12_MPP', 'M12_NUMBERS', 'M12_ONETOC', 'M12_OXPS', 'M12_PAGES', 'M12_PDF', 'M12_PNG', 'M12_TAR_GZ', 'M12_TXT', 'M12_WP', 'M12_WRI', 'M12_XHT', 'M12_XLA', 'M12_XLW', 'M12_XPS', 'M12_ZIP', 'M12_ZIPX', 'M09',], 'html':['M01_GIF', 'M01_JPG', 'M01_PDF', 'M01_PNG', 'M01_TAR_GZ', 'M01_ZIP', 'M02_GIF', 'M02_JPG', 'M02_JSBMP', 'M02_JSGIF', 'M02_PDF', 'M02_PNG', 'M02_ZIP', 'M04_ACE', 'M04_ARC', 'M04_ARJ', 'M04_BZ2', 'M04_DFXP', 'M04_EPUB', 'M04_GIF', 'M04_GPX', 'M04_GZIP', 'M04_JPG', 'M04_M4V', 'M04_MPA', 'M04_MPP', 'M04_NUMBERS', 'M04_ONETOC', 'M04_OXPS', 'M04_PAGES', 'M04_PDF', 'M04_PHAR', 'M04_PHP3', 'M04_PHP4', 'M04_PHP5', 'M04_PHP7', 'M04_PHTML', 'M04_PHT', 'M04_PNG', 'M04_TAR_GZ', 'M04_TXT', 'M04_WP', 'M04_WRI', 'M04_XHT', 'M04_XLA', 'M04_XLW', 'M04_XPS', 'M04_ZIP', 'M04_ZIPX', 'M06', 'M07', 'M08', 'M10', 'M11','M12_BZ2','M12_GIF','M12_PDF','M12_PNG','M12_TAR_GZ','M12_TXT','M12_JPG','M12_XHT','M12_ZIP'], 'xhtml':[ 'M04_ACE', 'M04_ARC', 'M04_ARJ', 'M04_BZ2', 'M04_DFXP', 'M04_EPUB', 'M04_GIF', 'M04_GPX', 'M04_GZIP', 'M04_JPG', 'M04_M4V', 'M04_MPA', 'M04_MPP', 'M04_NUMBERS', 'M04_ONETOC', 'M04_OXPS', 'M04_PAGES', 'M04_PDF', 'M04_PHAR', 'M04_PHP3', 'M04_PHP4', 'M04_PHP5', 'M04_PHP7', 'M04_PHTML', 'M04_PHT', 'M04_PNG', 'M04_TAR_GZ', 'M04_TXT', 'M04_WP', 'M04_WRI', 'M04_XHT', 'M04_XLA', 'M04_XLW', 'M04_XPS', 'M04_ZIP', 'M04_ZIPX', 'M06', 'M07', 'M08', 'M10', 'M11','M12_BZ2','M12_GIF','M12_JPG','M12_PNG','M12_TAR_GZ','M12_TXT','M12_ZIP','M12_PDF'], 'js':['M12_HTML','M12_XHTML','M10', 'M11','M12_GIF','M12_JPG','M12_PNG']}#['M01_GIF','M01_JPG', 'M01_PNG', 'M01_ZIP', 'M01_TAR_GZ', 'M01_PDF', 'M02_PNG', 'M02_JPG', 'M02_GIF', 'M02_ZIP', 'M02_PDF', 'M02_JSBMP', 'M02_JSGIF', 'M06', 'M04_JPG', 'M04_GIF', 'M04_ZIP', 'M04_TAR_GZ', 'M04_PDF', 'M04_PHP3', 'M04_PHP4', 'M04_PHP5', 'M04_PHP7', 'M04_PHAR', 'M04_PHT', 'M04_PHTML', 'M04_PNG', 'M04_TXT', 'M07_OTHER','M08'] # ([classname])when this op used for mutation,

                        # operations in this list can be used to extra mutation.
  __resource__ = {} # ({type:resource filename})
  __seed_dependency__ = __exclusion_op__.keys()#["html","js"] # seed file dependency for operation

  def operation(self, output, seed_file, resource_file=None):
      if output['filename'] != None and len(output['filename']) > 0:
        filename = output['filename']
      else:
        filename = utils.extract_filename(seed_file)
      #change = lambda a : chr(ord(a)+1)
      output['filename'] = filename + '_M10'
      #output['fileext'] = ''.join(map(change,list(output['fileext'])))
      output['fileext'] = 'fuse'
