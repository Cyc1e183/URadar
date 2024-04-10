from mutation_op import *

class mOP(MutationOP):
  __comment__ = "Mutation2 : set seed in resource file as metadata"
  __mutate_type__ = "file"  # (file|request) ; type of target
  __exclusion_op__ = {'php':['M03_ZIP', 'M03_JPG', 'M09','M01_GIF', 'M01_JPG', 'M01_PDF', 'M01_PNG', 'M01_TAR_GZ', 'M01_ZIP', 'M02_GIF', 'M02_JPG', 'M02_JSBMP', 'M02_JSGIF', 'M02_PDF', 'M02_PNG', 'M02_ZIP', 'M04_GIF', 'M04_GZIP', 'M04_JPG', 'M04_M4V', 'M04_PAGES', 'M04_PNG', 'M04_TAR_GZ', 'M04_XHT', 'M04_XLA', 'M04_ZIP', 'M12_GIF', 'M12_GZIP', 'M12_JPG', 'M12_M4V', 'M12_PAGES', 'M12_PNG', 'M12_TAR_GZ', 'M12_ZIP'], 'html':['M03_ZIP', 'M03_JPG', 'M01_GIF', 'M01_JPG', 'M01_PDF', 'M01_PNG', 'M01_TAR_GZ', 'M01_ZIP','M02_GIF', 'M02_JPG', 'M02_JSBMP', 'M02_JSGIF', 'M02_PDF', 'M02_PNG', 'M02_ZIP','M04_ACE','M04_ARC','M04_ARJ','M04_BZ2','M04_DFXP','M04_EPUB','M04_GPX','M04_GZIP','M04_M4V','M04_MPA','M04_MPP','M04_NUMBERS','M04_ONETOC','M04_OXPS','M04_PAGES','M04_WP','M04_WRI','M04_XHT','M04_XLA','M04_XLW','M04_XPS','M04_ZIPX','M06','M07','M08','M09','M10', 'M12_GIF', 'M12_GZIP', 'M12_JPG', 'M12_M4V', 'M12_PAGES', 'M12_PNG', 'M12_TAR_GZ', 'M12_ZIP']}#['M01_JPG', 'M01_PNG', 'M01_GIF', 'M01_ZIP', 'M01_TAR_GZ', 'M01_PDF', 'M02_PNG', 'M02_JPG', 'M02_GIF', 'M02_ZIP', 'M02_JSBMP', 'M02_JSGIF', 'M06', 'M08', 'M10', 'M07_OTHER'] # ([classname])when this op used for mutation,
                        # operations in this list can be used to extra mutation.
  __resource__ = {"jpg":""} # ({type:resource filename})
  __seed_dependency__ = __exclusion_op__.keys()#["php","html"] # seed file dependency for operation

  def operation(self, output, seed_file, resource_file=None):
    commentBlock = [b'\x25\xb5\x61',output['content'],b'\x0d\x0a']
    with open('./resource/test.pdf','rb') as fp:
      data = fp.read()

    output['content'] = data[:10]+b''.join(commentBlock)+data[10:]
    """
    with open('new.pdf','wb') as fp:
      fp.write(output['content'])
    """
    if output['filename'] != None and len(output['filename']) > 0:
      filename = output['filename']
    else:
      filename = utils.extract_filename(seed_file)
    output['filename'] = filename + '_M2PDF'
