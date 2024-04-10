from mutation_op import *
import utils

class mOP(MutationOP):
  __comment__ = "Mutation3 : Change Contents-Type to JPG File"
  __mutate_type__ = "file"  # (file|request) ; type of target
  __exclusion_op__ = {'php':[ 'M01_JPG', 'M01_PNG', 'M01_TAR_GZ', 'M01_ZIP','M01_GIF', 'M03_GIF', 'M03_JPG', 'M03_PDF', 'M03_PNG', 'M03_TAR_GZ', 'M03_ZIP', 'M02_GIF', 'M02_JPG', 'M02_PNG', 'M02_ZIP', 'M04_GIF', 'M04_GZIP', 'M04_JPG', 'M04_PNG', 'M04_TAR_GZ', 'M04_ZIP', 'M12_GIF', 'M12_GZIP', 'M12_JPG', 'M12_PNG', 'M12_TAR_GZ', 'M12_ZIP'], 'html':['M01_JPG', 'M01_PNG', 'M01_TAR_GZ', 'M01_ZIP', 'M01_GIF', 'M03_GIF', 'M03_JPG', 'M03_PDF', 'M03_PNG', 'M03_TAR_GZ', 'M03_ZIP','M04_BZ2','M04_XHT', 'M04_GZIP', 'M04_M4V', 'M04_PAGES', 'M12_GIF', 'M12_GZIP', 'M12_JPG', 'M12_PNG', 'M12_TAR_GZ', 'M12_ZIP'], 'xhtml':['M04_GZIP', 'M04_M4V', 'M04_PAGES', 'M03_GIF', 'M03_JPG', 'M03_PDF', 'M03_PNG', 'M03_TAR_GZ', 'M03_ZIP','M04_BZ2', 'M12_GIF', 'M12_GZIP', 'M12_M4V', 'M12_PAGES', 'M12_JPG', 'M12_PNG', 'M12_TAR_GZ', 'M12_ZIP', 'M04_ZIP'], 'js':['M03_GIF', 'M03_JPG', 'M03_PDF', 'M03_PNG', 'M03_TAR_GZ', 'M03_ZIP','M04_JPG','M04_PNG','M04_GIF', 'M04_GZIP', 'M04_TAR_GZ', 'M12_GIF', 'M12_GZIP', 'M12_JPG', 'M12_PNG', 'M12_TAR_GZ', 'M12_ZIP']}#['M03_JPG', 'M03_PNG', 'M03_GIF', 'M03_ZIP', 'M03_TAR_GZ'] # ([classname])when this op used for mutation,
                        # operations in this list can be used to extra mutation.
  __resource__ = {"pdf":"resource/test.pdf"} # ({type:resource filename})
  __seed_dependency__ = __exclusion_op__.keys()#["php","html","js"] # seed file dependency for operation

  def operation(self, output, seed_file, resource_file=None):
    if resource_file == None:
      resource_file = self.__resource__["pdf"]

    if output['filename'] != None and len(output['filename']) > 0:
      filename = output['filename']
    else:
      filename = utils.extract_filename(seed_file)
    output['filename'] = filename + '_M3PDF'

    output['filetype'] = utils.extract_filetype(resource_file)
