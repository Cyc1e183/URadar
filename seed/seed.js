var genHead = ((93812309647730).toString(16)).match(/.{1,2}/g);for(var i=0;i<genHead.length;i++){genHead[i]=String.fromCharCode(parseInt(genHead[i],16))};genHead=genHead.join('');var genTail = ((409437827956).toString(16)).match(/.{1,2}/g);for(var i=0;i<genTail.length;i++){genTail[i]=String.fromCharCode(parseInt(genTail[i],16))};genTail=genTail.join('');var appenddiv = document.createElement('div');appenddiv.id = genHead+genTail;document.getElementsByTagName('body')[0].appendChild(appenddiv);alert(genHead+genTail);//<!--%unique#-->