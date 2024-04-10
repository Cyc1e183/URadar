from mutation_op import *
import struct

class mOP(MutationOP):
  __comment__ = "Mutation2 : set seed in resource file as metadata"
  __mutate_type__ = "file"  # (file|request) ; type of target
  __exclusion_op__ = {'php':['M03_PDF', 'M03_ZIP','M09','M01_GIF', 'M01_JPG', 'M01_PDF', 'M01_PNG', 'M01_TAR_GZ', 'M01_ZIP', 'M02_GIF', 'M02_JPG', 'M02_JSBMP', 'M02_JSGIF', 'M02_PDF', 'M02_PNG', 'M02_ZIP', 'M04_GZIP', 'M04_JPG', 'M04_M4V', 'M04_PAGES', 'M04_PDF', 'M04_PNG', 'M04_TAR_GZ', 'M04_ZIP', 'M12_GZIP', 'M12_JPG', 'M12_M4V', 'M12_PAGES', 'M12_PDF', 'M12_PNG', 'M12_TAR_GZ', 'M12_ZIP'], 'html':['M03_PDF', 'M03_ZIP', 'M01_GIF', 'M01_JPG', 'M01_PDF', 'M01_PNG', 'M01_TAR_GZ', 'M01_ZIP','M02_GIF', 'M02_JPG', 'M02_JSBMP', 'M02_JSGIF', 'M02_PDF', 'M02_PNG', 'M02_ZIP','M04_ACE','M04_ARC','M04_ARJ','M04_BZ2','M04_DFXP','M04_EPUB','M04_GPX','M04_GZIP','M04_M4V','M04_MPA','M04_MPP','M04_NUMBERS','M04_ONETOC','M04_OXPS','M04_PAGES','M04_WP','M04_WRI','M04_XHT','M04_XLA','M04_XLW','M04_XPS','M04_ZIPX','M06','M07','M08','M09','M10', 'M12_GZIP', 'M12_JPG', 'M12_M4V', 'M12_PAGES', 'M12_PDF', 'M12_PNG', 'M12_TAR_GZ', 'M12_ZIP']}#['M01_JPG', 'M01_PNG', 'M01_GIF', 'M01_ZIP', 'M01_TAR_GZ', 'M01_PDF', 'M02_PNG', 'M02_JPG', 'M02_ZIP', 'M02_PDF', 'M02_JSBMP', 'M02_JSGIF', 'M06', 'M07_OTHER', 'M08', 'M10'] # ([classname])when this op used for mutation,
                        # operations in this list can be used to extra mutation.
  __resource__ = {} # ({type:resource filename})
  __seed_dependency__ = __exclusion_op__.keys()#["html","php"] # seed file dependency for operation

  def operation(self, output, seed_file, resource_file=None):
    if len(output['content'])<256:
      commentBlock = [b'\x21\xFE',struct.pack('>B',len(output['content'])),output['content'],'\x00']
    else:
      commentBlock = [b'\x21\xFE',b'\xff']
      offset = 0xff
      commentBlock += [output['content'][:offset]]
      while len(output['content'][offset:])>0:
        semilen = ord(output['content'][offset])
        commentBlock += [struct.pack('>B',semilen)]
        pad = ""
        if semilen > len(output['content'][offset+1:]):
          pad += "\x0a"*(semilen-len(output['content'][offset+1:]))
        commentBlock += [output['content'][offset+1:offset+1+semilen]+pad]
        offset = offset+1+semilen-len(pad)

    with open('./resource/test.gif','rb') as fp:
      data = fp.read()

    output['content'] = data[:0x30d]+b''.join(commentBlock)+data[0x30d:]

    #with open('new.gif','wb') as fp:
    #  fp.write(output['content'])

    if output['filename'] != None and len(output['filename']) > 0:
      filename = output['filename']
    else:
      filename = utils.extract_filename(seed_file)
    output['filename'] = filename + '_M2GIF'
